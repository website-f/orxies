package ui

import "testing"

func TestSafeNext(t *testing.T) {
	cases := map[string]string{
		"":                  "/",
		"/":                 "/",
		"/sites":            "/sites",
		"/sites/foo.yml":    "/sites/foo.yml",
		"//evil.com":        "/", // protocol-relative → off-host
		"/\\evil.com":       "/", // backslash trick → off-host
		"https://evil.com":  "/", // absolute
		"http://evil.com":   "/", // absolute
		"evil.com":          "/", // no leading slash
		"javascript:alert1": "/", // scheme, no slash
	}
	for in, want := range cases {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}
