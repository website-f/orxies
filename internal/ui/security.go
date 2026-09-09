package ui

import (
	"net/http"
	"strconv"
	"time"

	"orxies/internal/audit"
	"orxies/internal/secmon"
)

// secView is the formatted security snapshot the Security page renders.
// Everything here is display-ready: templates do no arithmetic and no
// time formatting, which keeps the markup readable and the logic tested.
type secView struct {
	Available   bool
	Reason      string
	Window      string
	GeneratedAt string
	AuthLogOK   bool
	Fail2banOK  bool

	TotalFailures     string
	TotalInvalidUsers string
	TotalSuccesses    string
	UniqueAttackers   string
	BansActive        string
	BansTotal         string

	// AlertCount drives the nav badge and the headline banner.
	AlertCount int
	HighCount  int

	Hourly []uint32

	TopAttackers   []secIPRow
	TopUsernames   []secUserRow
	Successes      []secEventRow
	Hijacks        []secHijackRow
	RecentFailures []secEventRow
	RecentBans     []secEventRow
	AuditEvents    []secAuditRow

	Posture []postureRow
}

type secIPRow struct {
	IP        string
	Total     string
	Failures  string
	Invalid   string
	Successes string
	Bans      string
	Banned    bool
	LastSeen  string
	Danger    bool // succeeded here despite failing repeatedly
}

type secUserRow struct {
	User  string
	Count string
	Width int // percentage bar width, relative to the top entry
}

type secEventRow struct {
	Time string
	Kind string
	User string
	IP   string
	Port string
	Jail string
	Bad  bool
}

type secHijackRow struct {
	Last     string
	Count    string
	Method   string
	User     string
	IP       string
	Reason   string
	Severity string
	High     bool
}

type secAuditRow struct {
	Time   string
	User   string
	IP     string
	Action string
	Target string
	Result string
	Bad    bool
}

// postureRow is one security-feature check. Status is "ok", "warn" or
// "bad" so the template can style it without re-deriving severity.
type postureRow struct {
	Label  string
	Status string
	Detail string
}

const secTimeFmt = "02 Jan 15:04:05"

func (s *Server) secView() secView {
	snap := s.SecMon.Read()
	v := secView{
		Available:   snap.Available,
		Reason:      snap.Reason,
		Window:      snap.Window,
		GeneratedAt: snap.GeneratedAt.Format(secTimeFmt),
		AuthLogOK:   snap.AuthLogOK,
		Fail2banOK:  snap.Fail2banOK,
		Hourly:      snap.Hourly,
	}

	// The posture panel and the admin audit trail come from orxies'
	// own state, so they are useful even when the host logs are not
	// mounted — render them regardless of snap.Available.
	v.Posture = s.posture()
	v.AuditEvents = s.auditRows(60)

	if !snap.Available {
		return v
	}

	v.TotalFailures = group(snap.TotalFailures)
	v.TotalInvalidUsers = group(snap.TotalInvalidUsers)
	v.TotalSuccesses = group(snap.TotalSuccesses)
	v.UniqueAttackers = group(snap.UniqueAttackers)
	v.BansActive = group(snap.BansActive)
	v.BansTotal = group(snap.BansTotal)

	dangerIPs := map[string]bool{}
	for _, h := range snap.Hijacks {
		if h.Severity == "high" {
			dangerIPs[h.IP] = true
			v.HighCount++
		}
		v.Hijacks = append(v.Hijacks, secHijackRow{
			Last:     fmtTime(h.Last),
			Count:    group(h.Count),
			Method:   h.Kind.String(),
			User:     h.User,
			IP:       h.IP,
			Reason:   h.Reason,
			Severity: h.Severity,
			High:     h.Severity == "high",
		})
	}
	v.AlertCount = len(snap.Hijacks)

	for _, a := range snap.TopAttackers {
		v.TopAttackers = append(v.TopAttackers, secIPRow{
			IP:        a.IP,
			Total:     group(a.Total()),
			Failures:  group(a.Failures),
			Invalid:   group(a.InvalidUsers),
			Successes: group(a.Successes),
			Bans:      group(a.Bans),
			Banned:    a.Banned,
			LastSeen:  fmtTime(a.Last),
			Danger:    a.Successes > 0 || dangerIPs[a.IP],
		})
	}

	top := 0
	for _, u := range snap.TopUsernames {
		if u.Count > top {
			top = u.Count
		}
	}
	for _, u := range snap.TopUsernames {
		w := 0
		if top > 0 {
			w = u.Count * 100 / top
		}
		v.TopUsernames = append(v.TopUsernames, secUserRow{
			User: u.User, Count: group(u.Count), Width: w,
		})
	}

	v.Successes = eventRows(snap.Successes)
	v.RecentFailures = eventRows(snap.RecentFailures)
	v.RecentBans = eventRows(snap.RecentBans)
	return v
}

func eventRows(events []secmon.Event) []secEventRow {
	out := make([]secEventRow, 0, len(events))
	for _, e := range events {
		out = append(out, secEventRow{
			Time: fmtTime(e.Time),
			Kind: e.Kind.String(),
			User: e.User,
			IP:   e.IP,
			Port: e.Port,
			Jail: e.Jail,
			Bad:  e.Kind == secmon.KindAcceptedPassword,
		})
	}
	return out
}

func (s *Server) auditRows(n int) []secAuditRow {
	if s.AuditPath == "" {
		return nil
	}
	recs, err := audit.Tail(s.AuditPath, n)
	if err != nil {
		return nil
	}
	out := make([]secAuditRow, 0, len(recs))
	for _, r := range recs {
		t := r.Time
		if parsed, err := time.Parse(time.RFC3339, r.Time); err == nil {
			t = parsed.Local().Format(secTimeFmt)
		}
		out = append(out, secAuditRow{
			Time: t, User: r.User, IP: r.IP,
			Action: r.Action, Target: r.Target, Result: r.Result,
			// "fail"/"denied"/"locked" results are what an attempted
			// takeover of the admin panel looks like in this log.
			Bad: r.Result != "ok" && r.Result != "success" && r.Result != "",
		})
	}
	return out
}

// posture reports the state of orxies' own hardening controls. This is
// the half of "security monitoring" that isn't about attackers: it
// answers "are my defences actually switched on?".
func (s *Server) posture() []postureRow {
	var rows []postureRow

	if s.Global != nil {
		// Admin UI reachability. Binding to loopback is the intended
		// deployment; anything else is only safe with an allowlist.
		addr := s.Global.AdminAddr
		loopback := len(addr) >= 9 && (addr[:9] == "127.0.0.1" || addr[:6] == "[::1]:")
		switch {
		case loopback:
			rows = append(rows, postureRow{"Admin UI binding", "ok",
				addr + " — loopback only, reachable via SSH tunnel"})
		case len(s.Global.AdminAllowCIDRs) > 0:
			rows = append(rows, postureRow{"Admin UI binding", "warn",
				addr + " — exposed, but restricted to " + strconv.Itoa(len(s.Global.AdminAllowCIDRs)) + " CIDR(s)"})
		default:
			rows = append(rows, postureRow{"Admin UI binding", "bad",
				addr + " — reachable beyond loopback with NO IP allowlist"})
		}

		// Two-factor on every admin account.
		total, with2fa := len(s.Global.Admins), 0
		for _, a := range s.Global.Admins {
			if a.TOTPSecret != "" {
				with2fa++
			}
		}
		switch {
		case total == 0:
			rows = append(rows, postureRow{"Admin 2FA", "bad", "no admin accounts configured"})
		case with2fa == total:
			rows = append(rows, postureRow{"Admin 2FA", "ok",
				"TOTP enabled on all " + strconv.Itoa(total) + " admin account(s)"})
		case with2fa == 0:
			rows = append(rows, postureRow{"Admin 2FA", "bad",
				"no admin has TOTP — a leaked password is a full takeover"})
		default:
			rows = append(rows, postureRow{"Admin 2FA", "warn",
				strconv.Itoa(with2fa) + " of " + strconv.Itoa(total) + " admins have TOTP"})
		}

		if s.Global.AdminForceSecureCookie {
			rows = append(rows, postureRow{"Session cookies", "ok", "Secure flag forced; HSTS enabled"})
		} else {
			rows = append(rows, postureRow{"Session cookies", "warn",
				"Secure flag not forced — fine for loopback-only admin access"})
		}

		if s.Global.TrustForwardedHeaders {
			rows = append(rows, postureRow{"Forwarded headers", "warn",
				"X-Forwarded-* trusted — only correct behind another trusted proxy"})
		} else {
			rows = append(rows, postureRow{"Forwarded headers", "ok",
				"not trusted; orxies is the edge"})
		}
	}

	// Per-site protections, summarised. Guard the store: posture is a
	// read-only diagnostic and must never be the thing that panics the
	// page it is meant to reassure you about.
	if s.Store == nil {
		return rows
	}
	sites := s.Store.Snapshot()
	enabled, tls, rl, exploits, redirect := 0, 0, 0, 0, 0
	for _, site := range sites {
		if !site.Enabled {
			continue
		}
		enabled++
		if site.TLS.Auto || site.TLS.CertFile != "" {
			tls++
		}
		if site.RateLimit.Enabled {
			rl++
		}
		if site.BlockCommonExploits {
			exploits++
		}
		if site.HTTPToHTTPS {
			redirect++
		}
	}
	if enabled > 0 {
		rows = append(rows,
			postureRow{"Site TLS", statusFrac(tls, enabled),
				strconv.Itoa(tls) + " of " + strconv.Itoa(enabled) + " enabled sites serve HTTPS"},
			postureRow{"HTTP→HTTPS redirect", statusFrac(redirect, enabled),
				strconv.Itoa(redirect) + " of " + strconv.Itoa(enabled) + " redirect plaintext to TLS"},
			postureRow{"Rate limiting", statusFrac(rl, enabled),
				strconv.Itoa(rl) + " of " + strconv.Itoa(enabled) + " sites throttle requests (DDoS / brute-force cushion)"},
			postureRow{"Common-exploit blocking", statusFrac(exploits, enabled),
				strconv.Itoa(exploits) + " of " + strconv.Itoa(enabled) + " sites filter known exploit patterns"},
		)
	} else {
		rows = append(rows, postureRow{"Sites", "warn", "no enabled sites"})
	}

	return rows
}

// statusFrac grades "n of total" — all is ok, none is bad, some is warn.
func statusFrac(n, total int) string {
	switch {
	case total == 0 || n == 0:
		return "bad"
	case n == total:
		return "ok"
	default:
		return "warn"
	}
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format(secTimeFmt)
}

// group renders an int with thousands separators. Attack counts reach
// six figures on a public box, and "123761" is materially harder to
// read at a glance than "123,761".
func group(n int) string {
	s := strconv.Itoa(n)
	neg := false
	if len(s) > 0 && s[0] == '-' {
		neg, s = true, s[1:]
	}
	if len(s) <= 3 {
		if neg {
			return "-" + s
		}
		return s
	}
	lead := len(s) % 3
	if lead == 0 {
		lead = 3
	}
	out := s[:lead]
	for i := lead; i < len(s); i += 3 {
		out += "," + s[i:i+3]
	}
	if neg {
		return "-" + out
	}
	return out
}

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/security" {
		http.NotFound(w, r)
		return
	}
	type data struct {
		baseData
		Sec secView
	}
	s.render(w, "layout", data{
		baseData: s.page(w, r, "Security", "security", "security"),
		Sec:      s.secView(),
	})
}

// handleSecurityPartial serves the poll target so the page refreshes
// without a full reload.
func (s *Server) handleSecurityPartial(w http.ResponseWriter, r *http.Request) {
	s.render(w, "security-body", s.secView())
}
