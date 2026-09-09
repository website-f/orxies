package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestEdgeHeadersCoverTheBasics(t *testing.T) {
	h := EdgeHeaders()
	for _, k := range []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Permissions-Policy",
	} {
		if h[k] == "" {
			t.Errorf("missing baseline header %q", k)
		}
	}
	if h["X-Content-Type-Options"] != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", h["X-Content-Type-Options"])
	}
	// SAMEORIGIN, not DENY: DENY also blocks a site framing its own pages.
	if h["X-Frame-Options"] != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options = %q, want SAMEORIGIN", h["X-Frame-Options"])
	}
}

// A blind CSP breaks React/Inertia upstreams, so it must NOT be in the
// default set — it's an opt-in, per-app decision.
func TestEdgeHeadersShipsNoBlindCSP(t *testing.T) {
	if v, ok := EdgeHeaders()["Content-Security-Policy"]; ok {
		t.Errorf("default set includes a CSP (%q); that has to be per-app", v)
	}
}

// HSTS must never be in the static map — it depends on the request
// being TLS, and sending it over plaintext is at best useless.
func TestEdgeHeadersExcludesHSTS(t *testing.T) {
	if _, ok := EdgeHeaders()["Strict-Transport-Security"]; ok {
		t.Error("HSTS must be applied conditionally, not from the static map")
	}
}

func TestMergeEdgeHeadersLetsSiteOverride(t *testing.T) {
	merged := MergeEdgeHeaders(map[string]string{
		"X-Frame-Options":         "DENY",               // override
		"Content-Security-Policy": "default-src 'self'", // addition
	})

	if merged["X-Frame-Options"] != "DENY" {
		t.Errorf("site override lost: got %q", merged["X-Frame-Options"])
	}
	if merged["Content-Security-Policy"] != "default-src 'self'" {
		t.Error("site addition lost")
	}
	// Untouched baseline entries must survive the merge.
	if merged["X-Content-Type-Options"] != "nosniff" {
		t.Error("merge dropped a baseline header")
	}
}

// The merge must not mutate the shared baseline, or one site's override
// would leak into every other site on the next reload.
func TestMergeEdgeHeadersDoesNotMutateBaseline(t *testing.T) {
	_ = MergeEdgeHeaders(map[string]string{"X-Frame-Options": "DENY"})
	if EdgeHeaders()["X-Frame-Options"] != "SAMEORIGIN" {
		t.Error("MergeEdgeHeaders mutated the baseline set")
	}
}

func TestEdgeHSTSOnlyOverTLS(t *testing.T) {
	if got := EdgeHSTS(false); got != "" {
		t.Errorf("HSTS over plaintext = %q, want empty", got)
	}
	got := EdgeHSTS(true)
	if got == "" {
		t.Fatal("no HSTS over TLS")
	}
	if !strings.Contains(got, "max-age=") {
		t.Errorf("HSTS missing max-age: %q", got)
	}
	// includeSubDomains would force HTTPS on subdomains whose cert
	// isn't issued (ws.staging.rizqmall.com has no DNS record), making
	// them permanently unreachable. preload requires it, so also out.
	if strings.Contains(got, "includeSubDomains") {
		t.Errorf("HSTS should not include subdomains yet: %q", got)
	}
	if strings.Contains(got, "preload") {
		t.Errorf("HSTS preload is a one-way door: %q", got)
	}
}
