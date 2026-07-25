package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"jobcloud/internal/auth"
	"jobcloud/internal/config"
	"jobcloud/internal/metrics"
)

// newTestServer builds a UI server with a single admin (password "pw",
// no 2FA) and returns its handler.
func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	hash, err := auth.HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	g := &config.Global{
		SessionSecret: "0123456789abcdef0123456789abcdef0123456789abcdef",
		Admins:        []config.Admin{{Username: "admin", PasswordHash: hash}},
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

var csrfField = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// login performs GET /login then POST /login with the given next, and
// returns the final POST response.
func login(t *testing.T, h http.Handler, next string) *http.Response {
	t.Helper()
	// GET to obtain a CSRF cookie + token.
	getReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	getRes := getRec.Result()
	var csrfCookie *http.Cookie
	for _, c := range getRes.Cookies() {
		if c.Name == "jobcloud_csrf" {
			csrfCookie = c
		}
	}
	if csrfCookie == nil {
		t.Fatal("no csrf cookie issued on GET /login")
	}
	m := csrfField.FindSubmatch(getRec.Body.Bytes())
	if m == nil {
		t.Fatal("no csrf_token field in login form")
	}
	token := string(m[1])

	form := url.Values{}
	form.Set("csrf_token", token)
	form.Set("username", "admin")
	form.Set("password", "pw")
	form.Set("next", next)
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func TestLoginRedirectHonorsLocalNext(t *testing.T) {
	h := newTestServer(t)
	res := login(t, h, "/sites")
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/sites" {
		t.Errorf("Location = %q, want /sites", loc)
	}
}

func TestLoginRedirectBlocksOffHostNext(t *testing.T) {
	h := newTestServer(t)
	for _, bad := range []string{"//evil.com", "/\\evil.com", "https://evil.com"} {
		res := login(t, h, bad)
		loc := res.Header.Get("Location")
		if loc != "/" {
			t.Errorf("next=%q → Location=%q, want / (no off-host redirect)", bad, loc)
		}
	}
}

func TestLoginRejectsMissingCSRF(t *testing.T) {
	h := newTestServer(t)
	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", "pw")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST /login without CSRF = %d, want 403", rec.Code)
	}
}
