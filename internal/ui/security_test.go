package ui

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"orxies/internal/config"
	"orxies/internal/secmon"
)

// renderSecurity renders the security body for a Server built from the
// given global config and log files.
func renderSecurity(t *testing.T, srv *Server) string {
	t.Helper()
	s, err := New(srv)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := s.tpl.ExecuteTemplate(&buf, "security-body", s.secView()); err != nil {
		t.Fatalf("render security-body: %v", err)
	}
	return buf.String()
}

const testAuthLog = `2026-09-06T00:01:13.623162+02:00 h sshd[1]: Failed password for root from 37.111.53.110 port 59482 ssh2
2026-09-06T00:01:14.623162+02:00 h sshd[1]: Invalid user wallet from 37.111.53.110 port 59483 ssh2
2026-09-06T00:02:13.623162+02:00 h sshd[1]: Accepted publickey for root from 118.101.146.127 port 5001 ssh2: ED25519 SHA256:x
2026-09-06T00:03:13.623162+02:00 h sshd[1]: Accepted password for root from 61.6.41.99 port 5002 ssh2
`

const testFail2banLog = `2026-09-06 00:05:27,860 fail2ban.actions [1]: NOTICE  [sshd] Ban 37.111.53.110
`

func writeLogs(t *testing.T) (authPath, banPath string) {
	t.Helper()
	dir := t.TempDir()
	authPath = filepath.Join(dir, "auth.log")
	banPath = filepath.Join(dir, "fail2ban.log")
	if err := os.WriteFile(authPath, []byte(testAuthLog), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(banPath, []byte(testFail2banLog), 0o600); err != nil {
		t.Fatal(err)
	}
	return authPath, banPath
}

func TestSecurityPageRendersAttackData(t *testing.T) {
	authPath, banPath := writeLogs(t)
	out := renderSecurity(t, &Server{
		SecMon: secmon.NewReader(secmon.Config{AuthLog: authPath, Fail2banLog: banPath}),
		Global: &config.Global{AdminAddr: "127.0.0.1:8090"},
	})

	for _, want := range []string{
		"Failed passwords",
		"Unique attackers",
		"37.111.53.110",   // the attacker
		"118.101.146.127", // a clean key login
		"wallet",          // username the botnet tried
		"Top attacking addresses",
		"Every accepted login",
		"banned", // fail2ban state chip
		"Hardening posture",
	} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("security page missing %q", want)
		}
	}
}

// A password login is the thing this page exists to surface, so it must
// reach the "needs review" panel rather than being buried in a table.
func TestSecurityPageFlagsPasswordLogin(t *testing.T) {
	authPath, banPath := writeLogs(t)
	out := renderSecurity(t, &Server{
		SecMon: secmon.NewReader(secmon.Config{AuthLog: authPath, Fail2banLog: banPath}),
		Global: &config.Global{AdminAddr: "127.0.0.1:8090"},
	})
	if !bytes.Contains([]byte(out), []byte("Logins needing review")) {
		t.Error("password login did not raise the review panel")
	}
	if !bytes.Contains([]byte(out), []byte("61.6.41.99")) {
		t.Error("the flagged login's source IP is not shown")
	}
}

// When the host logs are not mounted the page must say what to do, not
// render empty panels that read as "no attacks".
func TestSecurityPageUnavailableExplainsFix(t *testing.T) {
	out := renderSecurity(t, &Server{
		SecMon: secmon.NewReader(secmon.Config{AuthLog: filepath.Join(t.TempDir(), "missing.log")}),
		Global: &config.Global{AdminAddr: "127.0.0.1:8090"},
	})
	if !bytes.Contains([]byte(out), []byte("group_add")) {
		t.Error("unavailable state should name the group_add fix")
	}
	if !bytes.Contains([]byte(out), []byte("not found")) {
		t.Error("unavailable state should explain the source is missing")
	}
	// Posture must still render — it comes from orxies' own config.
	if !bytes.Contains([]byte(out), []byte("Hardening posture")) {
		t.Error("posture panel should render even without host logs")
	}
}

// The admin CSP forbids inline styles, so a style="" attribute would
// silently not apply in the browser. Catch it here instead.
func TestSecurityPageHasNoInlineStyles(t *testing.T) {
	authPath, banPath := writeLogs(t)
	out := renderSecurity(t, &Server{
		SecMon: secmon.NewReader(secmon.Config{AuthLog: authPath, Fail2banLog: banPath}),
		Global: &config.Global{AdminAddr: "127.0.0.1:8090"},
	})
	if bytes.Contains([]byte(out), []byte("style=")) {
		t.Error("security page uses an inline style attribute, which the admin CSP blocks")
	}
	if bytes.Contains([]byte(out), []byte("<style")) {
		t.Error("security page embeds a <style> block, which the admin CSP blocks")
	}
}

func TestPostureGradesAdminExposure(t *testing.T) {
	tests := []struct {
		name       string
		global     *config.Global
		wantStatus string
	}{
		{"loopback is ok", &config.Global{AdminAddr: "127.0.0.1:8090"}, "ok"},
		{"public with allowlist warns", &config.Global{AdminAddr: "0.0.0.0:8090",
			AdminAllowCIDRs: []string{"10.0.0.0/8"}}, "warn"},
		{"public without allowlist is bad", &config.Global{AdminAddr: "0.0.0.0:8090"}, "bad"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(&Server{Global: tc.global})
			if err != nil {
				t.Fatal(err)
			}
			rows := s.posture()
			var got string
			for _, r := range rows {
				if r.Label == "Admin UI binding" {
					got = r.Status
				}
			}
			if got != tc.wantStatus {
				t.Errorf("admin binding status = %q, want %q", got, tc.wantStatus)
			}
		})
	}
}

// 2FA is the control that protects against a leaked admin password, so
// its posture row must be graded strictly.
func TestPostureGrades2FA(t *testing.T) {
	tests := []struct {
		name   string
		admins []config.Admin
		want   string
	}{
		{"all have totp", []config.Admin{{Username: "a", TOTPSecret: "S1"}}, "ok"},
		{"none have totp", []config.Admin{{Username: "a"}}, "bad"},
		{"partial", []config.Admin{{Username: "a", TOTPSecret: "S1"}, {Username: "b"}}, "warn"},
		{"no admins", nil, "bad"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(&Server{Global: &config.Global{AdminAddr: "127.0.0.1:8090", Admins: tc.admins}})
			if err != nil {
				t.Fatal(err)
			}
			var got string
			for _, r := range s.posture() {
				if r.Label == "Admin 2FA" {
					got = r.Status
				}
			}
			if got != tc.want {
				t.Errorf("2FA status = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGroupThousands(t *testing.T) {
	cases := map[int]string{
		0: "0", 7: "7", 42: "42", 999: "999",
		1000: "1,000", 12345: "12,345", 123761: "123,761", 1000000: "1,000,000",
		-4567: "-4,567",
	}
	for in, want := range cases {
		if got := group(in); got != want {
			t.Errorf("group(%d) = %q, want %q", in, got, want)
		}
	}
}

// The admin audit trail is what shows an attempted takeover of the
// panel itself, so failures must be marked as such.
func TestAuditRowsMarkFailures(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	lines := `{"time":"2026-09-06T00:00:00Z","user":"admin","ip":"1.2.3.4","action":"login","result":"fail"}
{"time":"2026-09-06T00:01:00Z","user":"admin","ip":"5.6.7.8","action":"login","result":"ok"}
not-json
`
	if err := os.WriteFile(p, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(&Server{AuditPath: p})
	if err != nil {
		t.Fatal(err)
	}
	rows := s.auditRows(10)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (malformed line should be skipped)", len(rows))
	}
	// Newest first.
	if rows[0].Result != "ok" || rows[0].Bad {
		t.Errorf("successful login marked bad: %+v", rows[0])
	}
	if rows[1].Result != "fail" || !rows[1].Bad {
		t.Errorf("failed login not marked bad: %+v", rows[1])
	}
	if rows[0].Time == "2026-09-06T00:01:00Z" {
		t.Error("timestamp was not reformatted for display")
	}
}

// A nil SecMon must not panic the page (the feature is optional).
func TestSecViewWithoutSecMon(t *testing.T) {
	s, err := New(&Server{Global: &config.Global{AdminAddr: "127.0.0.1:8090"}})
	if err != nil {
		t.Fatal(err)
	}
	v := s.secView()
	if v.Available {
		t.Error("expected unavailable without a reader")
	}
	if len(v.Posture) == 0 {
		t.Error("posture should still be produced")
	}
	_ = time.Now()
}
