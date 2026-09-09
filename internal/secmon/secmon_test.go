package secmon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Real lines captured from an Ubuntu 24.04 host under active
// brute-force. Using verbatim samples is the point: a parser validated
// only against invented lines is how you end up shipping a monitor
// that silently reports zero attacks.
const realAuthLog = `2026-09-06T00:01:13.623162+02:00 vmi3212282 sshd[3028945]: Failed password for root from 151.158.2.135 port 59482 ssh2
2026-09-06T00:07:11.692481+02:00 vmi3212282 sshd[3035562]: Invalid user postgres from 45.153.34.181 port 56936
2026-09-06T00:07:22.667791+02:00 vmi3212282 sshd[3035773]: Invalid user ubuntu from 43.129.193.109 port 37382
2026-09-06T00:08:01.000000+02:00 vmi3212282 sshd[3035774]: Failed password for invalid user ubuntu from 43.129.193.109 port 37382 ssh2
2026-09-06T00:34:42.874363+02:00 vmi3212282 sshd[3064940]: userauth_pubkey: signature algorithm ssh-rsa not in PubkeyAcceptedAlgorithms [preauth]
2026-09-06T01:00:00.000000+02:00 vmi3212282 sshd[3064941]: Accepted password for root from 118.101.146.127 port 51234 ssh2
2026-09-06T01:05:00.000000+02:00 vmi3212282 sshd[3064942]: Accepted publickey for root from 118.101.146.127 port 51299 ssh2: ED25519 SHA256:abc123
2026-09-06T01:06:00.000000+02:00 vmi3212282 sshd[3064943]: error: maximum authentication attempts exceeded for root from 37.111.53.110 port 40001 ssh2 [preauth]
2026-09-06T01:07:00.000000+02:00 vmi3212282 CRON[123]: pam_unix(cron:session): session opened for user root
`

const realFail2banLog = `2026-09-06 00:05:27,860 fail2ban.actions        [1544044]: NOTICE  [sshd] Ban 195.178.110.227
2026-09-06 00:05:31,913 fail2ban.actions        [1544044]: NOTICE  [sshd] Unban 37.111.53.110
2026-09-06 00:07:27,083 fail2ban.actions        [1544044]: NOTICE  [sshd] Ban 45.153.34.181
2026-09-06 00:09:00,000 fail2ban.filter         [1544044]: INFO    [sshd] Found 1.2.3.4
`

func TestParseAuthLineRFC3339(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name string
		line string
		kind Kind
		user string
		ip   string
		port string
	}{
		{"failed password", `2026-09-06T00:01:13.623162+02:00 h sshd[1]: Failed password for root from 151.158.2.135 port 59482 ssh2`,
			KindFailedPassword, "root", "151.158.2.135", "59482"},
		{"failed invalid user", `2026-09-06T00:08:01.000000+02:00 h sshd[1]: Failed password for invalid user ubuntu from 43.129.193.109 port 37382 ssh2`,
			KindFailedPassword, "ubuntu", "43.129.193.109", "37382"},
		{"invalid user", `2026-09-06T00:07:11.692481+02:00 h sshd[1]: Invalid user postgres from 45.153.34.181 port 56936`,
			KindInvalidUser, "postgres", "45.153.34.181", "56936"},
		{"accepted password", `2026-09-06T01:00:00.000000+02:00 h sshd[1]: Accepted password for root from 118.101.146.127 port 51234 ssh2`,
			KindAcceptedPassword, "root", "118.101.146.127", "51234"},
		{"accepted publickey", `2026-09-06T01:05:00.000000+02:00 h sshd[1]: Accepted publickey for root from 118.101.146.127 port 51299 ssh2: ED25519 SHA256:abc`,
			KindAcceptedKey, "root", "118.101.146.127", "51299"},
		{"max auth tries", `2026-09-06T01:06:00.000000+02:00 h sshd[1]: error: maximum authentication attempts exceeded for root from 37.111.53.110 port 40001 ssh2 [preauth]`,
			KindMaxAuthTries, "root", "37.111.53.110", "40001"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, ok := parseAuthLine(tc.line, now)
			if !ok {
				t.Fatalf("line not parsed: %s", tc.line)
			}
			if e.Kind != tc.kind {
				t.Errorf("kind = %v, want %v", e.Kind, tc.kind)
			}
			if e.User != tc.user {
				t.Errorf("user = %q, want %q", e.User, tc.user)
			}
			if e.IP != tc.ip {
				t.Errorf("ip = %q, want %q", e.IP, tc.ip)
			}
			if e.Port != tc.port {
				t.Errorf("port = %q, want %q", e.Port, tc.port)
			}
			if e.Time.IsZero() {
				t.Error("timestamp not parsed")
			}
		})
	}
}

func TestParseAuthLineTraditionalSyslog(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.Local)
	e, ok := parseAuthLine(`Sep  6 00:01:13 host sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2`, now)
	if !ok {
		t.Fatal("traditional syslog line not parsed")
	}
	if e.IP != "1.2.3.4" || e.User != "root" || e.Kind != KindFailedPassword {
		t.Fatalf("unexpected parse: %+v", e)
	}
	if e.Time.IsZero() {
		t.Fatal("timestamp not parsed")
	}
	if got := e.Time.Year(); got != 2026 {
		t.Errorf("year = %d, want 2026 (inferred from now)", got)
	}
	if e.Time.Month() != time.September || e.Time.Day() != 6 {
		t.Errorf("date = %v, want Sep 6", e.Time)
	}
}

// A December log read in January must not be dated in the future.
func TestTraditionalSyslogYearRollback(t *testing.T) {
	now := time.Date(2027, 1, 5, 12, 0, 0, 0, time.Local)
	e, ok := parseAuthLine(`Dec 28 23:59:00 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2`, now)
	if !ok {
		t.Fatal("not parsed")
	}
	if e.Time.After(now) {
		t.Errorf("time %v is in the future relative to %v", e.Time, now)
	}
	if e.Time.Year() != 2026 {
		t.Errorf("year = %d, want 2026", e.Time.Year())
	}
}

func TestParseAuthLineIgnoresNoise(t *testing.T) {
	now := time.Now()
	noise := []string{
		"",
		`2026-09-06T00:34:42.874363+02:00 h sshd[1]: userauth_pubkey: signature algorithm ssh-rsa not in PubkeyAcceptedAlgorithms [preauth]`,
		`2026-09-06T01:07:00.000000+02:00 h CRON[123]: pam_unix(cron:session): session opened for user root`,
		`2026-09-06T01:07:00.000000+02:00 h sshd[1]: Received disconnect from 1.2.3.4 port 22:11: Bye Bye [preauth]`,
	}
	for _, line := range noise {
		if _, ok := parseAuthLine(line, now); ok {
			t.Errorf("noise line was parsed as an event: %s", line)
		}
	}
}

func TestParseFail2banLine(t *testing.T) {
	e, ok := parseFail2banLine(`2026-09-06 00:05:27,860 fail2ban.actions        [1544044]: NOTICE  [sshd] Ban 195.178.110.227`)
	if !ok {
		t.Fatal("ban line not parsed")
	}
	if e.Kind != KindBan {
		t.Errorf("kind = %v, want ban", e.Kind)
	}
	if e.IP != "195.178.110.227" {
		t.Errorf("ip = %q", e.IP)
	}
	if e.Jail != "sshd" {
		t.Errorf("jail = %q, want sshd", e.Jail)
	}
	if e.Time.IsZero() {
		t.Error("timestamp not parsed")
	}

	// "Found" lines duplicate sshd's own record and must be ignored.
	if _, ok := parseFail2banLine(`2026-09-06 00:09:00,000 fail2ban.filter [1] : INFO [sshd] Found 1.2.3.4`); ok {
		t.Error("Found line should not be treated as an action")
	}
}

func TestSnapshotAggregation(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth.log")
	banPath := filepath.Join(dir, "fail2ban.log")
	if err := os.WriteFile(authPath, []byte(realAuthLog), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(banPath, []byte(realFail2banLog), 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewReader(Config{AuthLog: authPath, Fail2banLog: banPath})
	s := r.Read()

	if !s.Available {
		t.Fatalf("snapshot unavailable: %s", s.Reason)
	}
	if !s.AuthLogOK || !s.Fail2banOK {
		t.Fatalf("sources not both OK: auth=%v f2b=%v reason=%s", s.AuthLogOK, s.Fail2banOK, s.Reason)
	}
	// 2 "Failed password" + 1 max-auth-tries = 3 failures; 2 invalid users.
	if s.TotalFailures != 3 {
		t.Errorf("TotalFailures = %d, want 3", s.TotalFailures)
	}
	if s.TotalInvalidUsers != 2 {
		t.Errorf("TotalInvalidUsers = %d, want 2", s.TotalInvalidUsers)
	}
	if s.TotalSuccesses != 2 {
		t.Errorf("TotalSuccesses = %d, want 2", s.TotalSuccesses)
	}
	if s.BansTotal != 2 {
		t.Errorf("BansTotal = %d, want 2", s.BansTotal)
	}
	// 195.178.110.227 was banned and never unbanned -> active.
	// 45.153.34.181 banned last -> active. 37.111.53.110 unbanned -> not.
	if s.BansActive != 2 {
		t.Errorf("BansActive = %d, want 2", s.BansActive)
	}
	if len(s.Successes) != 2 {
		t.Errorf("Successes = %d, want 2", len(s.Successes))
	}
	if len(s.Hourly) != 24 {
		t.Errorf("Hourly buckets = %d, want 24", len(s.Hourly))
	}
}

// A password login from an address with many failures is the signature
// this page exists to surface.
func TestClassifyHijacksFlagsBruteForceSuccess(t *testing.T) {
	attacker := "37.111.53.110"
	stats := map[string]*IPStat{
		attacker:  {IP: attacker, Failures: 500},
		"1.1.1.1": {IP: "1.1.1.1"},
	}
	successes := []Event{
		{IP: attacker, Kind: KindAcceptedPassword, User: "root", Time: time.Now()},
		{IP: "1.1.1.1", Kind: KindAcceptedKey, User: "root", Time: time.Now()},
	}
	h := classifyHijacks(successes, stats)
	if len(h) != 1 {
		t.Fatalf("got %d hijack flags, want 1 (%+v)", len(h), h)
	}
	if h[0].IP != attacker {
		t.Errorf("flagged %s, want %s", h[0].IP, attacker)
	}
	if h[0].Severity != "high" {
		t.Errorf("severity = %q, want high", h[0].Severity)
	}
}

// Regression: an admin who mistypes a password once and then logs in
// legitimately must NOT be graded "high". Running against a real host
// log, a 1-failure threshold flagged every genuine session as a
// probable takeover and drowned the panel.
func TestClassifyHijacksToleratesMistypedPassword(t *testing.T) {
	ip := "118.101.146.127"
	stats := map[string]*IPStat{ip: {IP: ip, Failures: 1}}
	var successes []Event
	base := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 17; i++ {
		successes = append(successes, Event{
			IP: ip, Kind: KindAcceptedPassword, User: "root",
			Time: base.Add(time.Duration(i) * time.Minute),
		})
	}
	h := classifyHijacks(successes, stats)

	// Grouped into a single row, not 17.
	if len(h) != 1 {
		t.Fatalf("got %d rows, want 1 grouped row", len(h))
	}
	if h[0].Count != 17 {
		t.Errorf("Count = %d, want 17", h[0].Count)
	}
	if h[0].Severity != "medium" {
		t.Errorf("severity = %q, want medium — one typo is not a brute-force", h[0].Severity)
	}
	if h[0].Last.Before(h[0].First) {
		t.Error("Last should be at or after First")
	}
}

// Grouping must not merge distinct principals.
func TestClassifyHijacksGroupsByPrincipal(t *testing.T) {
	stats := map[string]*IPStat{
		"1.1.1.1": {IP: "1.1.1.1"},
		"2.2.2.2": {IP: "2.2.2.2"},
	}
	successes := []Event{
		{IP: "1.1.1.1", Kind: KindAcceptedPassword, User: "root", Time: time.Now()},
		{IP: "1.1.1.1", Kind: KindAcceptedPassword, User: "deploy", Time: time.Now()},
		{IP: "2.2.2.2", Kind: KindAcceptedPassword, User: "root", Time: time.Now()},
	}
	if h := classifyHijacks(successes, stats); len(h) != 3 {
		t.Fatalf("got %d rows, want 3 distinct (ip,user) groups", len(h))
	}
}

// High-severity rows must sort above medium ones so the row that
// matters is the first one read.
func TestClassifyHijacksOrdersHighFirst(t *testing.T) {
	stats := map[string]*IPStat{
		"9.9.9.9": {IP: "9.9.9.9"},                 // clean -> medium
		"8.8.8.8": {IP: "8.8.8.8", Failures: 4000}, // brute force -> high
	}
	now := time.Now()
	successes := []Event{
		{IP: "9.9.9.9", Kind: KindAcceptedPassword, User: "root", Time: now},                 // newer
		{IP: "8.8.8.8", Kind: KindAcceptedPassword, User: "root", Time: now.Add(-time.Hour)}, // older but high
	}
	h := classifyHijacks(successes, stats)
	if len(h) != 2 {
		t.Fatalf("got %d rows, want 2", len(h))
	}
	if h[0].Severity != "high" {
		t.Errorf("first row severity = %q, want high (severity outranks recency)", h[0].Severity)
	}
}

// A clean key login must never be flagged — false alarms train
// operators to ignore the page.
func TestClassifyHijacksIgnoresCleanKeyLogin(t *testing.T) {
	stats := map[string]*IPStat{"9.9.9.9": {IP: "9.9.9.9"}}
	h := classifyHijacks([]Event{{IP: "9.9.9.9", Kind: KindAcceptedKey}}, stats)
	if len(h) != 0 {
		t.Errorf("clean key login was flagged: %+v", h)
	}
}

func TestMissingSourcesDegradeGracefully(t *testing.T) {
	r := NewReader(Config{AuthLog: filepath.Join(t.TempDir(), "nope.log")})
	s := r.Read()
	if s.Available {
		t.Error("snapshot should be unavailable when no source can be read")
	}
	if s.Reason == "" {
		t.Error("Reason should explain why it is unavailable")
	}
}

func TestNilReaderIsSafe(t *testing.T) {
	var r *Reader
	s := r.Read()
	if s.Available {
		t.Error("nil reader should report unavailable")
	}
}

// readTail must start on a line boundary so the first record parsed is
// never a fragment of a longer line.
func TestReadTailStartsOnLineBoundary(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.log")
	content := "AAAAAAAAAAAAAAAAAAAA\nBBBB\nCCCC\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := readTail(p, 12) // lands mid-way through the first line
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if got != "BBBB\nCCCC\n" && got != "CCCC\n" {
		t.Errorf("readTail returned a partial line: %q", got)
	}
}
