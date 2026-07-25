package proxy

import (
	"net/http"
	"os"
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
//
// If spa is true, any request that doesn't resolve to a real file falls
// back to index.html — the behavior single-page apps and Next.js/Vite
// static exports need for client-side routing.
func staticHandler(root string, spa bool) http.Handler {
	fs := http.FileServer(noListDir{http.Dir(root)})
	if !spa {
		return fs
	}
	index := filepath.Join(root, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Re-root the cleaned request path so "../" can't escape root.
		rel := filepath.Clean("/" + r.URL.Path)
		if st, err := os.Stat(filepath.Join(root, rel)); err == nil && !st.IsDir() {
			fs.ServeHTTP(w, r) // real asset (css/js/img) — let FileServer do it
			return
		}
		http.ServeFile(w, r, index) // deep link → hand back the app shell
	})
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
