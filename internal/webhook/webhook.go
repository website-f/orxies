// Package webhook handles Git provider "push" webhooks so a `git push`
// redeploys a project automatically. It lives on the PUBLIC edge (80/443)
// — not the loopback admin UI — because providers must reach it, so it is
// gated by a per-project HMAC secret (GitHub's X-Hub-Signature-256).
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"orxies/internal/store"
)

// PathPrefix is the reserved edge path. The trailing segment is the
// project id: POST /_orxies/deploy/<id>.
const PathPrefix = "/_orxies/deploy/"

// Deployer triggers an async deploy for a project id.
type Deployer func(projectID int64)

// Handler intercepts webhook requests and delegates everything else to
// Next (the normal reverse-proxy router).
type Handler struct {
	Store  *store.Store
	Deploy Deployer
	Next   http.Handler
}

// New builds a webhook handler that falls through to next.
func New(st *store.Store, deploy Deployer, next http.Handler) *Handler {
	return &Handler{Store: st, Deploy: deploy, Next: next}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, PathPrefix) {
		h.Next.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, PathPrefix), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	p, err := h.Store.GetProject(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 5<<20)) // 5 MB cap
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if p.WebhookSecret == "" || !validSignature(p.WebhookSecret, body, r.Header.Get("X-Hub-Signature-256")) {
		slog.Warn("webhook rejected", "project", p.Name, "ip", peerIP(r))
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	// Acknowledge non-push events (e.g. GitHub's initial "ping") without
	// deploying, so the provider marks the hook healthy.
	if ev := r.Header.Get("X-GitHub-Event"); ev != "" && ev != "push" {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ignored: "+ev)
		return
	}
	slog.Info("webhook deploy triggered", "project", p.Name)
	if h.Deploy != nil {
		h.Deploy(id)
	}
	w.WriteHeader(http.StatusAccepted)
	io.WriteString(w, "deploy triggered")
}

// validSignature verifies GitHub's HMAC-SHA256 body signature.
func validSignature(secret string, body []byte, header string) bool {
	const pfx = "sha256="
	if !strings.HasPrefix(header, pfx) {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(strings.TrimPrefix(header, pfx)))
}

func peerIP(r *http.Request) string {
	if i := strings.LastIndexByte(r.RemoteAddr, ':'); i >= 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}
