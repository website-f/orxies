// Package secmon turns host security telemetry into something an
// operator can actually read: who is attacking SSH, which of those
// attempts succeeded, and what fail2ban did about it.
//
// It is deliberately read-only and best-effort. The admin UI runs
// unprivileged in a container, so the log files it wants live on the
// host and arrive via read-only bind mounts. When a source is missing
// or unreadable the snapshot degrades to Available=false with a reason
// rather than failing the page — the same contract the System page
// uses for non-Linux hosts.
//
// Logs get large (a month of brute-force on a public box is tens of
// megabytes), so parsing always reads a bounded window from the END of
// the file. A monitor is about what is happening now; loading the whole
// file to answer that would be wasteful and, on a 256MB container,
// dangerous.
package secmon

import (
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultTailBytes is how much of each log's tail is parsed. ~4MB is
// roughly 30k sshd lines — far more than a 24h view needs, while
// staying trivially cheap to read.
const DefaultTailBytes = 4 << 20

// Config points the reader at its sources. Empty paths disable that
// source; a disabled source is reported, not silently skipped, so the
// UI can tell the operator what to mount.
type Config struct {
	// AuthLog is the sshd/PAM log (Debian/Ubuntu: /var/log/auth.log,
	// RHEL: /var/log/secure).
	AuthLog string
	// Fail2banLog is fail2ban's own log, used for ban/unban history.
	Fail2banLog string
	// TailBytes overrides DefaultTailBytes when non-zero.
	TailBytes int64
	// MaxEvents caps how many individual events each list retains.
	MaxEvents int
	// CacheTTL is how long a snapshot is reused. The page polls, so
	// without this every poll would re-read megabytes.
	CacheTTL time.Duration
}

func (c Config) tailBytes() int64 {
	if c.TailBytes > 0 {
		return c.TailBytes
	}
	return DefaultTailBytes
}

func (c Config) maxEvents() int {
	if c.MaxEvents > 0 {
		return c.MaxEvents
	}
	return 200
}

func (c Config) cacheTTL() time.Duration {
	if c.CacheTTL > 0 {
		return c.CacheTTL
	}
	return 15 * time.Second
}

// Kind classifies one security event.
type Kind uint8

const (
	KindFailedPassword   Kind = iota // wrong password for a real account
	KindInvalidUser                  // login attempt for an account that doesn't exist
	KindAcceptedPassword             // SUCCESSFUL password login
	KindAcceptedKey                  // SUCCESSFUL public-key login
	KindMaxAuthTries                 // client burned through MaxAuthTries
	KindBan                          // fail2ban banned an IP
	KindUnban                        // fail2ban released an IP
)

// String renders a Kind for display.
func (k Kind) String() string {
	switch k {
	case KindFailedPassword:
		return "failed password"
	case KindInvalidUser:
		return "invalid user"
	case KindAcceptedPassword:
		return "accepted password"
	case KindAcceptedKey:
		return "accepted key"
	case KindMaxAuthTries:
		return "max auth tries"
	case KindBan:
		return "ban"
	case KindUnban:
		return "unban"
	}
	return "unknown"
}

// Event is one parsed log line.
type Event struct {
	Time time.Time
	Kind Kind
	User string
	IP   string
	Port string
	Jail string // fail2ban only
}

// IPStat aggregates everything seen from one source address.
type IPStat struct {
	IP           string
	Failures     int
	InvalidUsers int
	Successes    int
	First        time.Time
	Last         time.Time
	Banned       bool // currently held by fail2ban (per the log's last action)
	Bans         int  // how many times it has been banned
}

// Total attempts from this IP, successful or not.
func (s IPStat) Total() int { return s.Failures + s.InvalidUsers + s.Successes }

// UserStat counts attempts against one username.
type UserStat struct {
	User  string
	Count int
}

// Snapshot is one complete, self-consistent security view.
type Snapshot struct {
	Available   bool
	Reason      string // why unavailable, or a partial-source warning
	GeneratedAt time.Time
	Window      string // human description of the period covered
	From, To    time.Time

	TotalFailures     int
	TotalInvalidUsers int
	TotalSuccesses    int
	UniqueAttackers   int

	BansTotal  int
	BansActive int
	Fail2banOK bool
	AuthLogOK  bool

	TopAttackers []IPStat
	TopUsernames []UserStat

	// Successes lists every accepted login in the window. On a
	// key-only box this list should contain nothing but your own
	// addresses, which makes it the highest-signal panel on the page.
	Successes []Event
	// Hijacks are successes that warrant a second look — see
	// classifyHijacks for the rules.
	Hijacks []Hijack
	// RecentFailures is the raw tail, newest first, for the log view.
	RecentFailures []Event
	RecentBans     []Event

	// Hourly is failure counts bucketed into the last 24 hours,
	// oldest first, for a sparkline.
	Hourly []uint32
}

// Hijack is a group of successful logins flagged as suspicious.
//
// Logins are grouped by (IP, user, method) rather than listed one per
// row: a normal admin racks up dozens of legitimate sessions a day, and
// one row each would bury the single row that actually matters.
type Hijack struct {
	IP            string
	User          string
	Kind          Kind
	Count         int
	First, Last   time.Time
	Reason        string
	Severity      string // "high" | "medium"
	PriorFailures int
}

// Reader produces cached Snapshots. Safe for concurrent use.
type Reader struct {
	cfg Config

	mu   sync.Mutex
	last Snapshot
	at   time.Time
}

// NewReader returns a Reader for cfg.
func NewReader(cfg Config) *Reader { return &Reader{cfg: cfg} }

// Read returns a Snapshot, reusing a cached one inside CacheTTL.
// A nil *Reader yields an unavailable snapshot, so callers that never
// wired the feature need no nil guard.
func (r *Reader) Read() Snapshot {
	if r == nil {
		return Snapshot{Reason: "security monitoring is not configured"}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.at.IsZero() && time.Since(r.at) < r.cfg.cacheTTL() {
		return r.last
	}
	s := r.build()
	r.last, r.at = s, time.Now()
	return s
}

// build does the actual parse + aggregate.
func (r *Reader) build() Snapshot {
	s := Snapshot{GeneratedAt: time.Now()}
	var problems []string

	// ---- sshd auth log ----
	var authEvents []Event
	if r.cfg.AuthLog == "" {
		problems = append(problems, "auth_log not configured")
	} else {
		ev, err := parseAuthLog(r.cfg.AuthLog, r.cfg.tailBytes())
		switch {
		case err != nil:
			problems = append(problems, authLogProblem(r.cfg.AuthLog, err))
		default:
			authEvents = ev
			s.AuthLogOK = true
		}
	}

	// ---- fail2ban log ----
	var banEvents []Event
	if r.cfg.Fail2banLog == "" {
		problems = append(problems, "fail2ban_log not configured")
	} else {
		ev, err := parseFail2banLog(r.cfg.Fail2banLog, r.cfg.tailBytes())
		switch {
		case err != nil:
			problems = append(problems, authLogProblem(r.cfg.Fail2banLog, err))
		default:
			banEvents = ev
			s.Fail2banOK = true
		}
	}

	s.Available = s.AuthLogOK || s.Fail2banOK
	s.Reason = strings.Join(problems, "; ")
	if !s.Available {
		return s
	}

	// ---- aggregate ----
	stats := map[string]*IPStat{}
	users := map[string]int{}
	touch := func(ip string, t time.Time) *IPStat {
		st := stats[ip]
		if st == nil {
			st = &IPStat{IP: ip, First: t, Last: t}
			stats[ip] = st
		}
		if !t.IsZero() {
			if st.First.IsZero() || t.Before(st.First) {
				st.First = t
			}
			if t.After(st.Last) {
				st.Last = t
			}
		}
		return st
	}

	for _, e := range authEvents {
		if e.IP == "" {
			continue
		}
		st := touch(e.IP, e.Time)
		switch e.Kind {
		case KindFailedPassword, KindMaxAuthTries:
			st.Failures++
			s.TotalFailures++
			if e.User != "" {
				users[e.User]++
			}
		case KindInvalidUser:
			st.InvalidUsers++
			s.TotalInvalidUsers++
			if e.User != "" {
				users[e.User]++
			}
		case KindAcceptedPassword, KindAcceptedKey:
			st.Successes++
			s.TotalSuccesses++
			s.Successes = append(s.Successes, e)
		}
	}

	// Ban state: the LAST action per IP decides whether it is held now.
	lastAction := map[string]Kind{}
	for _, e := range banEvents {
		if e.IP == "" {
			continue
		}
		st := touch(e.IP, e.Time)
		if e.Kind == KindBan {
			st.Bans++
			s.BansTotal++
			s.RecentBans = append(s.RecentBans, e)
		}
		lastAction[e.IP] = e.Kind
	}
	for ip, k := range lastAction {
		if k == KindBan {
			if st := stats[ip]; st != nil {
				st.Banned = true
				s.BansActive++
			}
		}
	}

	s.UniqueAttackers = 0
	for _, st := range stats {
		if st.Failures+st.InvalidUsers > 0 {
			s.UniqueAttackers++
		}
	}

	// Top attackers by total attempts.
	s.TopAttackers = make([]IPStat, 0, len(stats))
	for _, st := range stats {
		if st.Failures+st.InvalidUsers == 0 {
			continue // a clean successful login is not an "attacker"
		}
		s.TopAttackers = append(s.TopAttackers, *st)
	}
	sort.Slice(s.TopAttackers, func(i, j int) bool {
		a, b := s.TopAttackers[i], s.TopAttackers[j]
		if a.Total() != b.Total() {
			return a.Total() > b.Total()
		}
		return a.IP < b.IP
	})
	if len(s.TopAttackers) > 30 {
		s.TopAttackers = s.TopAttackers[:30]
	}

	// Top usernames.
	s.TopUsernames = make([]UserStat, 0, len(users))
	for u, c := range users {
		s.TopUsernames = append(s.TopUsernames, UserStat{User: u, Count: c})
	}
	sort.Slice(s.TopUsernames, func(i, j int) bool {
		a, b := s.TopUsernames[i], s.TopUsernames[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.User < b.User
	})
	if len(s.TopUsernames) > 20 {
		s.TopUsernames = s.TopUsernames[:20]
	}

	s.Hijacks = classifyHijacks(s.Successes, stats)

	// Newest-first raw views, capped.
	s.RecentFailures = tailFiltered(authEvents, r.cfg.maxEvents(), func(e Event) bool {
		return e.Kind == KindFailedPassword || e.Kind == KindInvalidUser || e.Kind == KindMaxAuthTries
	})
	reverse(s.RecentBans)
	if len(s.RecentBans) > r.cfg.maxEvents() {
		s.RecentBans = s.RecentBans[:r.cfg.maxEvents()]
	}
	reverse(s.Successes)

	s.Hourly = hourlyFailures(authEvents, s.GeneratedAt)
	s.From, s.To = windowOf(authEvents, banEvents)
	s.Window = humanWindow(s.From, s.To)
	return s
}

// BruteForceFailureThreshold is how many failed attempts an address
// must have produced before a success from it is treated as a probable
// brute-force landing.
//
// It is deliberately not 1. A real admin mistypes a password, then gets
// it right; treating that as a takeover flags every legitimate session
// and the panel becomes noise. Twenty failures is well beyond fumbling
// and far below what a real brute-force needs.
const BruteForceFailureThreshold = 20

// classifyHijacks flags successful logins that deserve attention,
// grouped by (IP, user, method).
//
// The rules encode what actually matters on a hardened box:
//   - a success from an address that also produced *many* failures is
//     the classic signature of a brute-force that finally landed;
//   - a password login is a milder anomaly once key-only auth is
//     enforced, because it should be impossible at all.
//
// Everything else is reported as a plain success, not an alert. False
// alarms train operators to ignore the page.
func classifyHijacks(successes []Event, stats map[string]*IPStat) []Hijack {
	type key struct {
		ip, user string
		kind     Kind
	}
	idx := map[key]*Hijack{}
	var order []key

	for _, e := range successes {
		prior := 0
		if st := stats[e.IP]; st != nil {
			prior = st.Failures + st.InvalidUsers
		}

		var severity, reason string
		switch {
		case prior >= BruteForceFailureThreshold:
			severity = "high"
			reason = "succeeded from an address with " + itoa(prior) +
				" failed attempts — possible brute-force success"
		case e.Kind == KindAcceptedPassword:
			severity = "medium"
			reason = "password login — should be impossible once key-only auth is enforced"
			if prior > 0 {
				reason += " (" + itoa(prior) + " failed attempt(s) from this address)"
			}
		default:
			continue // a clean key login is not an alert
		}

		k := key{e.IP, e.User, e.Kind}
		h := idx[k]
		if h == nil {
			h = &Hijack{
				IP: e.IP, User: e.User, Kind: e.Kind,
				First: e.Time, Last: e.Time,
				Severity: severity, Reason: reason, PriorFailures: prior,
			}
			idx[k] = h
			order = append(order, k)
		}
		h.Count++
		if !e.Time.IsZero() {
			if h.First.IsZero() || e.Time.Before(h.First) {
				h.First = e.Time
			}
			if e.Time.After(h.Last) {
				h.Last = e.Time
			}
		}
	}

	out := make([]Hijack, 0, len(order))
	for _, k := range order {
		out = append(out, *idx[k])
	}
	// Highest severity first, then most recent.
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.Severity == "high") != (b.Severity == "high") {
			return a.Severity == "high"
		}
		return a.Last.After(b.Last)
	})
	return out
}

// hourlyFailures buckets failures into the 24 hours ending at now.
func hourlyFailures(events []Event, now time.Time) []uint32 {
	const buckets = 24
	out := make([]uint32, buckets)
	start := now.Add(-time.Duration(buckets-1) * time.Hour).Truncate(time.Hour)
	for _, e := range events {
		if e.Kind != KindFailedPassword && e.Kind != KindInvalidUser {
			continue
		}
		if e.Time.IsZero() || e.Time.Before(start) {
			continue
		}
		i := int(e.Time.Sub(start) / time.Hour)
		if i >= 0 && i < buckets {
			out[i]++
		}
	}
	return out
}

// tailFiltered returns up to n matching events, newest first.
func tailFiltered(events []Event, n int, keep func(Event) bool) []Event {
	out := make([]Event, 0, n)
	for i := len(events) - 1; i >= 0 && len(out) < n; i-- {
		if keep(events[i]) {
			out = append(out, events[i])
		}
	}
	return out
}

func reverse(e []Event) {
	for i, j := 0, len(e)-1; i < j; i, j = i+1, j-1 {
		e[i], e[j] = e[j], e[i]
	}
}

func windowOf(sets ...[]Event) (from, to time.Time) {
	for _, set := range sets {
		for _, e := range set {
			if e.Time.IsZero() {
				continue
			}
			if from.IsZero() || e.Time.Before(from) {
				from = e.Time
			}
			if e.Time.After(to) {
				to = e.Time
			}
		}
	}
	return from, to
}

func humanWindow(from, to time.Time) string {
	if from.IsZero() || to.IsZero() {
		return "no dated events in the parsed window"
	}
	d := to.Sub(from).Truncate(time.Minute)
	switch {
	case d >= 48*time.Hour:
		return itoa(int(d.Hours())/24) + " days of log tail"
	case d >= time.Hour:
		return itoa(int(d.Hours())) + "h of log tail"
	default:
		return itoa(int(d.Minutes())) + "m of log tail"
	}
}

// authLogProblem turns a file error into operator-actionable text.
// "permission denied" on these logs almost always means the container
// is missing the adm group rather than the mount, so say so.
func authLogProblem(path string, err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return path + " not found (bind-mount it into the container read-only)"
	case errors.Is(err, os.ErrPermission):
		return path + " unreadable — these logs are mode 640 root:adm, so the container needs group_add: \"4\" (adm)"
	default:
		return path + ": " + err.Error()
	}
}

// readTail returns the last max bytes of path, starting at a line
// boundary so the first record is never a fragment.
func readTail(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	off := int64(0)
	if size > max {
		off = size - max
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if off > 0 {
		// Drop the partial first line.
		if i := indexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	return b, nil
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// itoa avoids pulling strconv into template-facing string building.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
