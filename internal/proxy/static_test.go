package proxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jobcloud/internal/config"
	"jobcloud/internal/metrics"
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
