package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"orxies/internal/store"
)

func setup(t *testing.T) (*store.Store, int64) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	p := &store.Project{Name: "app", Domain: "app.test", Strategy: "dockerfile", RepoURL: "x", WebhookSecret: "topsecret"}
	if err := db.CreateProject(p); err != nil {
		t.Fatal(err)
	}
	return db, p.ID
}

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func post(t *testing.T, h http.Handler, id int64, body []byte, sig, event string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, PathPrefix+strconv.FormatInt(id, 10), bytes.NewReader(body))
	if sig != "" {
		req.Header.Set("X-Hub-Signature-256", sig)
	}
	if event != "" {
		req.Header.Set("X-GitHub-Event", event)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestWebhookValidTriggersDeploy(t *testing.T) {
	db, id := setup(t)
	var got int64 = -1
	h := New(db, func(pid int64) { got = pid }, http.NotFoundHandler())
	body := []byte(`{"ref":"refs/heads/main"}`)
	rec := post(t, h, id, body, sign("topsecret", body), "push")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("code=%d, want 202", rec.Code)
	}
	if got != id {
		t.Errorf("deploy triggered for %d, want %d", got, id)
	}
}

func TestWebhookBadSignatureRejected(t *testing.T) {
	db, id := setup(t)
	called := false
	h := New(db, func(int64) { called = true }, http.NotFoundHandler())
	rec := post(t, h, id, []byte(`{}`), "sha256=deadbeef", "push")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code=%d, want 401", rec.Code)
	}
	if called {
		t.Error("deploy must not fire on a bad signature")
	}
}

func TestWebhookPingIgnored(t *testing.T) {
	db, id := setup(t)
	called := false
	h := New(db, func(int64) { called = true }, http.NotFoundHandler())
	body := []byte(`{"zen":"hi"}`)
	rec := post(t, h, id, body, sign("topsecret", body), "ping")
	if rec.Code != http.StatusOK {
		t.Errorf("ping code=%d, want 200", rec.Code)
	}
	if called {
		t.Error("ping must not trigger a deploy")
	}
}

func TestWebhookFallsThroughToNext(t *testing.T) {
	db, _ := setup(t)
	nextHit := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextHit = true })
	h := New(db, func(int64) {}, next)
	req := httptest.NewRequest(http.MethodGet, "/some/site/path", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !nextHit {
		t.Error("non-webhook request should fall through to Next (the router)")
	}
}
