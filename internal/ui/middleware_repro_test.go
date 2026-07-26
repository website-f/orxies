package ui

import (
	"net/http"
	"testing"

	"orxies/internal/security"
)

// Reproduce the live server's exact admin middleware chain and confirm
// next-threading + CSRF still behave (guards against MaxBody/body-wrap
// interference with ParseForm).
func wrapAdmin(h http.Handler) http.Handler {
	return security.Headers(security.IPAllowlist(nil, security.MaxBody(64<<10, h)), false)
}

func TestLoginRedirectThroughMiddleware(t *testing.T) {
	h := wrapAdmin(newTestServer(t))
	res := login(t, h, "/sites")
	if loc := res.Header.Get("Location"); loc != "/sites" {
		t.Errorf("through middleware: next=/sites → Location=%q, want /sites", loc)
	}
	res = login(t, h, "//evil.com")
	if loc := res.Header.Get("Location"); loc != "/" {
		t.Errorf("through middleware: next=//evil.com → Location=%q, want /", loc)
	}
}
