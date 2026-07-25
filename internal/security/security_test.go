package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestIPAllowlist(t *testing.T) {
	allow, err := ParseCIDRs([]string{"10.0.0.0/8", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	h := IPAllowlist(allow, okHandler())

	cases := map[string]int{
		"10.1.2.3:5555":    http.StatusOK,
		"127.0.0.1:5555":   http.StatusOK,
		"192.168.1.9:5555": http.StatusForbidden,
		"8.8.8.8:5555":     http.StatusForbidden,
	}
	for addr, want := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("peer %s → %d, want %d", addr, rec.Code, want)
		}
	}
}

func TestIPAllowlistEmptyIsPassthrough(t *testing.T) {
	h := IPAllowlist(nil, okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("empty allowlist should pass through, got %d", rec.Code)
	}
}

func TestIPAllowlistIgnoresForwardedHeader(t *testing.T) {
	allow, _ := ParseCIDRs([]string{"10.0.0.0/8"})
	h := IPAllowlist(allow, okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:1234"               // real peer: blocked
	req.Header.Set("X-Forwarded-For", "10.0.0.5") // spoof attempt: must be ignored
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("allowlist must ignore X-Forwarded-For, got %d", rec.Code)
	}
}

func TestHeadersSet(t *testing.T) {
	h := Headers(okHandler(), true)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	want := []string{
		"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
		"Referrer-Policy", "Strict-Transport-Security",
	}
	for _, k := range want {
		if rec.Header().Get(k) == "" {
			t.Errorf("missing header %s", k)
		}
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
}

func TestHeadersNoHSTSWithoutTLS(t *testing.T) {
	h := Headers(okHandler(), false)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must not be sent when not TLS-fronted")
	}
}
