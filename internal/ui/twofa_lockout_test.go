package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"orxies/internal/auth"
	"orxies/internal/config"
	"orxies/internal/metrics"
)

var pendingField = regexp.MustCompile(`name="pending" value="([^"]+)"`)

func newTestServerCommon(t *testing.T, admin config.Admin) http.Handler {
	t.Helper()
	g := &config.Global{
		SessionSecret: "0123456789abcdef0123456789abcdef0123456789abcdef",
		Admins:        []config.Admin{admin},
	}
	am, err := auth.New(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(&Server{
		Store:   config.NewStore(),
		Metrics: metrics.NewRegistry(),
		Auth:    am,
		StartAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s.Handler()
}

// getCSRF returns a fresh csrf cookie + token from GET /login.
func getCSRF(t *testing.T, h http.Handler) (*http.Cookie, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	var c *http.Cookie
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "orxies_csrf" {
			c = ck
		}
	}
	if c == nil {
		t.Fatal("no csrf cookie")
	}
	m := csrfField.FindSubmatch(rec.Body.Bytes())
	if m == nil {
		t.Fatal("no csrf field")
	}
	return c, string(m[1])
}

func postForm(h http.Handler, cookie *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestLogin2FAFlow(t *testing.T) {
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := auth.HashPassword("pw")
	h := newTestServerCommon(t, config.Admin{Username: "admin", PasswordHash: hash, TOTPSecret: secret})

	// Stage 1: correct password → must NOT log in; must present 2FA form.
	c, tok := getCSRF(t, h)
	f := url.Values{"csrf_token": {tok}, "username": {"admin"}, "password": {"pw"}}
	rec := postForm(h, c, f)
	if rec.Code != http.StatusOK {
		t.Fatalf("password stage: code=%d, want 200 (2FA form)", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Fatal("password stage issued a redirect — 2FA was bypassed!")
	}
	pm := pendingField.FindSubmatch(rec.Body.Bytes())
	if pm == nil {
		t.Fatal("no pending token in 2FA form")
	}
	pending := string(pm[1])

	// Stage 2a: wrong code → stay on 2FA form.
	rec = postForm(h, c, url.Values{"csrf_token": {tok}, "pending": {pending}, "otp": {"000000"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Invalid authentication code") {
		t.Fatalf("wrong code: code=%d, want 200 with error", rec.Code)
	}

	// Stage 2b: correct code → logged in (303 + session cookie).
	code, err := auth.CurrentCode(secret)
	if err != nil {
		t.Fatal(err)
	}
	rec = postForm(h, c, url.Values{"csrf_token": {tok}, "pending": {pending}, "otp": {code}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("correct code: code=%d, want 303", rec.Code)
	}
	var gotSession bool
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "orxies_session" && ck.Value != "" {
			gotSession = true
		}
	}
	if !gotSession {
		t.Error("no session cookie issued after successful 2FA")
	}
}

func TestLoginLockout(t *testing.T) {
	hash, _ := auth.HashPassword("pw")
	h := newTestServerCommon(t, config.Admin{Username: "admin", PasswordHash: hash})

	// 5 wrong passwords from the same peer → 6th attempt is locked out,
	// even with the *correct* password.
	for i := 0; i < 5; i++ {
		c, tok := getCSRF(t, h)
		rec := postForm(h, c, url.Values{"csrf_token": {tok}, "username": {"admin"}, "password": {"wrong"}})
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: code=%d, want 200 (error re-render)", i+1, rec.Code)
		}
	}
	c, tok := getCSRF(t, h)
	rec := postForm(h, c, url.Values{"csrf_token": {tok}, "username": {"admin"}, "password": {"pw"}})
	if rec.Header().Get("Location") != "" {
		t.Fatal("locked-out account still logged in with correct password!")
	}
	if !strings.Contains(rec.Body.String(), "Too many attempts") {
		t.Errorf("expected lockout message, got body:\n%s", rec.Body.String())
	}
}
