package proxy

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// staticHandler serves a site's files directly from a directory, so a
// raw-HTML / portfolio / static-export site needs no sidecar server.
//
// Security posture:
//   - Directory listings are disabled (a dir with no index.html → 404),
//     matching the admin UI's static hardening.
//   - Path traversal is prevented by http.Dir (which cleans and rejects
//     "..") and, on the SPA path, by re-rooting the cleaned request path
//     under root before touching the filesystem.
//   - Dot-segments are refused (see hiddenPath) so a site served out of
//     a Git checkout never hands over its .git directory.
//
// If spa is true, any request that doesn't resolve to a real file falls
// back to index.html — the behavior single-page apps and Next.js/Vite
// static exports need for client-side routing.
func staticHandler(root string, spa bool) http.Handler {
	fs := http.FileServer(noListDir{http.Dir(root)})
	inner := http.Handler(fs)
	if spa {
		index := filepath.Join(root, "index.html")
		inner = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Re-root the cleaned request path so "../" can't escape root.
			rel := filepath.Clean("/" + r.URL.Path)
			if st, err := os.Stat(filepath.Join(root, rel)); err == nil && !st.IsDir() {
				fs.ServeHTTP(w, r) // real asset (css/js/img) — let FileServer do it
				return
			}
			http.ServeFile(w, r, index) // deep link → hand back the app shell
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hiddenPath(path.Clean("/" + r.URL.Path)) {
			http.NotFound(w, r) // 404, not 403 — don't confirm what exists
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// hiddenPath reports whether any segment of a cleaned URL path starts
// with a dot. orxies deploys a static project straight from its Git
// checkout, so without this the whole repository — history included —
// would be readable at /.git/, along with any stray .env or .htpasswd
// in the tree. The one exception is /.well-known/, which exists to be
// public (security.txt, apple-app-site-association); ACME http-01
// challenges never reach here, the issuer's handler answers those
// before the router sees the request.
func hiddenPath(p string) bool {
	if strings.HasPrefix(p, "/.well-known/") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if len(seg) > 1 && seg[0] == '.' {
			return true
		}
	}
	return false
}

// noListDir wraps an http.FileSystem so opening a directory that has no
// index.html returns os.ErrNotExist — turning would-be directory
// listings into 404s instead of leaking a file index.
type noListDir struct{ fs http.FileSystem }

func (d noListDir) Open(name string) (http.File, error) {
	f, err := d.fs.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if info.IsDir() {
		index := strings.TrimSuffix(name, "/") + "/index.html"
		idx, err := d.fs.Open(index)
		if err != nil {
			f.Close()
			return nil, os.ErrNotExist
		}
		idx.Close()
	}
	return f, nil
}
