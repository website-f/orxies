package proxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"orxies/internal/config"
	"orxies/internal/metrics"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func serve(h http.Handler, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://x"+path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestStaticServesFilesNoListing(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "index.html"), "<h1>home</h1>")
	writeFile(t, filepath.Join(root, "app.css"), "body{color:red}")
	writeFile(t, filepath.Join(root, "assets", "nolist.txt"), "data") // subdir, no index.html

	h := staticHandler(root, false)

	if rec := serve(h, "/"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "home") {
		t.Errorf("GET / = %d %q, want 200 home", rec.Code, rec.Body.String())
	}
	if rec := serve(h, "/app.css"); rec.Code != 200 {
		t.Errorf("GET /app.css = %d, want 200", rec.Code)
	}
	// Directory with no index.html must 404 — never a listing.
	rec := serve(h, "/assets/")
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /assets/ = %d, want 404 (no dir listing)", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "nolist.txt") {
		t.Errorf("directory listing leaked filenames: %q", rec.Body.String())
	}
	if rec := serve(h, "/missing"); rec.Code != http.StatusNotFound {
		t.Errorf("GET /missing = %d, want 404", rec.Code)
	}
}

func TestStaticSPAFallback(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "index.html"), "<div id=app>shell</div>")
	writeFile(t, filepath.Join(root, "app.js"), "console.log(1)")

	h := staticHandler(root, true)

	// Deep link with no matching file → app shell (index.html), 200.
	if rec := serve(h, "/dashboard/settings"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "shell") {
		t.Errorf("SPA deep link = %d %q, want 200 shell", rec.Code, rec.Body.String())
	}
	// Real asset still served as itself.
	if rec := serve(h, "/app.js"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "console.log") {
		t.Errorf("SPA asset = %d %q, want the js file", rec.Code, rec.Body.String())
	}
}

func TestRouterServesRelativeStaticRoot(t *testing.T) {
	www := t.TempDir()
	writeFile(t, filepath.Join(www, "portfolio", "index.html"), "<h1>portfolio</h1>")

	store := config.NewStore()
	r := NewRouter(store, metrics.NewRegistry(), false, www)
	site := &config.Site{Domain: "p.test", Root: "portfolio", Enabled: true}
	store.Replace([]*config.Site{site})
	r.Reload([]*config.Site{site})

	req := httptest.NewRequest(http.MethodGet, "http://p.test/", nil)
	req.Host = "p.test"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "portfolio") {
		t.Errorf("router static (relative root) = %d %q, want 200 portfolio", rec.Code, rec.Body.String())
	}
}

// A static project is served straight out of its Git checkout, so the
// repository itself must never be readable over HTTP.
func TestStaticHidesDotPaths(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "index.html"), "<h1>home</h1>")
	writeFile(t, filepath.Join(root, ".git", "config"), "[remote \"origin\"]")
	writeFile(t, filepath.Join(root, ".git", "HEAD"), "ref: refs/heads/main")
	writeFile(t, filepath.Join(root, ".env"), "SECRET=hunter2")
	writeFile(t, filepath.Join(root, "assets", ".htpasswd"), "user:hash")
	writeFile(t, filepath.Join(root, ".well-known", "security.txt"), "Contact: mailto:a@b.c")

	for _, spa := range []bool{false, true} {
		h := staticHandler(root, spa)
		for _, p := range []string{"/.git/config", "/.git/HEAD", "/.env", "/assets/.htpasswd"} {
			rec := serve(h, p)
			if rec.Code != http.StatusNotFound {
				t.Errorf("spa=%v GET %s = %d, want 404", spa, p, rec.Code)
			}
			for _, leak := range []string{"origin", "refs/heads", "hunter2", "user:hash"} {
				if strings.Contains(rec.Body.String(), leak) {
					t.Errorf("spa=%v GET %s leaked %q", spa, p, leak)
				}
			}
		}
		// /.well-known/ is public by design and must still be served.
		if rec := serve(h, "/.well-known/security.txt"); rec.Code != 200 ||
			!strings.Contains(rec.Body.String(), "mailto:a@b.c") {
			t.Errorf("spa=%v GET /.well-known/security.txt = %d %q, want the file",
				spa, rec.Code, rec.Body.String())
		}
		// Normal content is unaffected.
		if rec := serve(h, "/"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "home") {
			t.Errorf("spa=%v GET / = %d %q, want 200 home", spa, rec.Code, rec.Body.String())
		}
	}
}

func TestHiddenPath(t *testing.T) {
	cases := map[string]bool{
		"/":                               false,
		"/index.html":                     false,
		"/assets/app.css":                 false,
		"/.well-known/security.txt":       false,
		"/.well-known/acme-challenge/tok": false,
		"/.git":                           true,
		"/.git/config":                    true,
		"/deep/nested/.git/HEAD":          true,
		"/.env":                           true,
		"/sub/.hidden":                    true,
	}
	for p, want := range cases {
		if got := hiddenPath(p); got != want {
			t.Errorf("hiddenPath(%q) = %v, want %v", p, got, want)
		}
	}
}
