// Package agent is orxies's privileged orchestration component. It is
// the ONLY part of the system that talks to the Docker daemon; the
// unprivileged control plane drives it over a loopback unix socket
// guarded by a shared secret.
//
// Run it with `orxies agent`. The container image that runs it carries
// the `docker` and `nixpacks` binaries and mounts /var/run/docker.sock.
package agent

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
)

// BuildSpec describes how to turn a source directory into an image.
type BuildSpec struct {
	Name       string `json:"name"`        // image tag to produce (control plane decides)
	SourcePath string `json:"source_path"` // directory to build
	Strategy   string `json:"strategy"`    // "nixpacks" | "dockerfile"
	Dockerfile string `json:"dockerfile"`  // optional path relative to SourcePath
}

// RunSpec describes how to run a built image as a container.
type RunSpec struct {
	Name       string            `json:"name"`      // container name (control plane decides)
	Image      string            `json:"image"`     // image ref to run
	HostPort   int               `json:"host_port"` // 127.0.0.1:<HostPort> publish; 0 = don't publish
	AppPort    int               `json:"app_port"`  // port the app listens on inside
	Env        map[string]string `json:"env"`
	MemoryMB   int               `json:"memory_mb"`
	Network    string            `json:"network"`    // docker network to join ("" = default)
	Volumes    map[string]string `json:"volumes"`    // named volume -> container mount path
	Unhardened bool              `json:"unhardened"` // skip cap-drop/no-new-privileges (DB images need caps)
}

// ExecSpec runs a command inside a container (used for DB dump/restore).
type ExecSpec struct {
	Container string            `json:"container"`
	Env       map[string]string `json:"env"`
	Cmd       []string          `json:"cmd"`
}

// Status is a container's current state.
type Status struct {
	State   string `json:"state"` // running | exited | created | ""(absent)
	Running bool   `json:"running"`
}

// Health reports agent readiness.
type Health struct {
	OK       bool   `json:"ok"`
	Docker   bool   `json:"docker"`
	Nixpacks bool   `json:"nixpacks"`
	Detail   string `json:"detail,omitempty"`
}

// Runner is the container backend. The real implementation shells out
// to docker/nixpacks (docker.go); tests use a fake.
type Runner interface {
	Build(ctx context.Context, spec BuildSpec, logs io.Writer) error
	Run(ctx context.Context, spec RunSpec) (containerID string, err error)
	Stop(ctx context.Context, name string) error
	Remove(ctx context.Context, name string) error
	Logs(ctx context.Context, name string, tail int, w io.Writer) error
	Status(ctx context.Context, name string) (Status, error)
	EnsureNetwork(ctx context.Context, name string) error
	// ExecOut runs cmd in a container and streams stdout to w (DB dump).
	ExecOut(ctx context.Context, spec ExecSpec, w io.Writer) error
	// ExecIn runs cmd in a container feeding r as stdin (DB restore).
	ExecIn(ctx context.Context, spec ExecSpec, r io.Reader) error
	Health(ctx context.Context) Health
}

// Server exposes Runner over HTTP (served on a unix socket by Serve).
type Server struct {
	runner Runner
	secret []byte
}

// NewServer builds the agent HTTP server.
func NewServer(runner Runner, secret []byte) *Server {
	return &Server{runner: runner, secret: secret}
}

// Handler returns the authenticated mux (exported for tests).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/build", s.auth(s.handleBuild))
	mux.HandleFunc("/v1/run", s.auth(s.handleRun))
	mux.HandleFunc("/v1/stop", s.auth(s.handleStop))
	mux.HandleFunc("/v1/remove", s.auth(s.handleRemove))
	mux.HandleFunc("/v1/network", s.auth(s.handleNetwork))
	mux.HandleFunc("/v1/exec-out", s.auth(s.handleExecOut))
	mux.HandleFunc("/v1/exec-in", s.auth(s.handleExecIn))
	mux.HandleFunc("/v1/logs", s.auth(s.handleLogs))
	mux.HandleFunc("/v1/status", s.auth(s.handleStatus))
	mux.HandleFunc("/v1/health", s.auth(s.handleHealth))
	return mux
}

// auth enforces the shared secret in the Authorization header.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("Authorization")
		if len(s.secret) == 0 || !hmac.Equal([]byte(tok), s.secret) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleBuild(w http.ResponseWriter, r *http.Request) {
	var spec BuildSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// Stream build output straight to the client as it happens.
	fw := &flushWriter{w: w}
	if err := s.runner.Build(r.Context(), spec, fw); err != nil {
		// The stream has already started (200 sent); signal failure with
		// a trailer line the control plane checks for.
		io.WriteString(fw, "\norxies-build: FAILED: "+err.Error()+"\n")
		slog.Warn("agent build failed", "name", spec.Name, "err", err)
		return
	}
	io.WriteString(fw, "\norxies-build: OK\n")
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	var spec RunSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := s.runner.Run(r.Context(), spec)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"container_id": id})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) { s.byName(w, r, s.runner.Stop) }
func (s *Server) handleRemove(w http.ResponseWriter, r *http.Request) {
	s.byName(w, r, s.runner.Remove)
}

func (s *Server) byName(w http.ResponseWriter, r *http.Request, fn func(context.Context, string) error) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := fn(r.Context(), body.Name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleNetwork(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.runner.EnsureNetwork(r.Context(), body.Name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// handleExecOut streams a command's stdout (e.g. pg_dump) to the client.
// The exit status rides in a trailer so the body stays a clean dump.
func (s *Server) handleExecOut(w http.ResponseWriter, r *http.Request) {
	var spec ExecSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil || spec.Container == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Trailer", "X-Exec-Status")
	fw := &flushWriter{w: w}
	if err := s.runner.ExecOut(r.Context(), spec, fw); err != nil {
		w.Header().Set("X-Exec-Status", "error: "+err.Error())
		slog.Warn("exec-out failed", "container", spec.Container, "err", err)
		return
	}
	w.Header().Set("X-Exec-Status", "ok")
}

// handleExecIn feeds the request body to a command's stdin (DB restore).
// The spec rides in a header so the body is pure stdin.
func (s *Server) handleExecIn(w http.ResponseWriter, r *http.Request) {
	raw, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Exec-Spec"))
	if err != nil {
		http.Error(w, "bad spec", http.StatusBadRequest)
		return
	}
	var spec ExecSpec
	if json.Unmarshal(raw, &spec) != nil || spec.Container == "" {
		http.Error(w, "bad spec", http.StatusBadRequest)
		return
	}
	if err := s.runner.ExecIn(r.Context(), spec, r.Body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	tail := 200
	if v := r.URL.Query().Get("tail"); v != "" {
		if n, err := parseTail(v); err == nil {
			tail = n
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err := s.runner.Logs(r.Context(), name, tail, &flushWriter{w: w}); err != nil {
		slog.Warn("agent logs failed", "name", name, "err", err)
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	st, err := s.runner.Status(r.Context(), name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, st)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.runner.Health(r.Context()))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func parseTail(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errBadTail
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

var errBadTail = errStr("bad tail")

type errStr string

func (e errStr) Error() string { return string(e) }

// flushWriter flushes after every write so streamed logs appear live.
type flushWriter struct{ w http.ResponseWriter }

func (f *flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if fl, ok := f.w.(http.Flusher); ok {
		fl.Flush()
	}
	return n, err
}
