package ui

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"orxies/internal/deploy"
	"orxies/internal/store"
	"orxies/internal/webhook"
)

// logBuf is a concurrency-safe growing buffer for one project's most
// recent deploy output.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
func (l *logBuf) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b.Reset()
}

func (s *Server) logFor(id int64) *logBuf {
	s.projMu.Lock()
	defer s.projMu.Unlock()
	lb := s.projLogs[id]
	if lb == nil {
		lb = &logBuf{}
		s.projLogs[id] = lb
	}
	return lb
}

func (s *Server) setDeploying(id int64, v bool) {
	s.projMu.Lock()
	s.projDeploying[id] = v
	s.projMu.Unlock()
}
func (s *Server) isDeploying(id int64) bool {
	s.projMu.Lock()
	defer s.projMu.Unlock()
	return s.projDeploying[id]
}

// ---- list ----

type projectRow struct {
	*store.Project
	Status    string
	Deploying bool
}

func (s *Server) projectRows() []projectRow {
	ps, err := s.DB.ListProjects()
	if err != nil {
		return nil
	}
	rows := make([]projectRow, 0, len(ps))
	for _, p := range ps {
		status := "never deployed"
		if d, err := s.DB.LatestDeployment(p.ID); err == nil {
			status = d.Status
		}
		rows = append(rows, projectRow{Project: p, Status: status, Deploying: s.isDeploying(p.ID)})
	}
	return rows
}

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/projects" {
		http.NotFound(w, r)
		return
	}
	type data struct {
		baseData
		Projects []projectRow
	}
	s.render(w, "layout", data{
		baseData: s.page(w, r, "Projects", "projects", "projects"),
		Projects: s.projectRows(),
	})
}

// ---- new / create ----

type projectFormData struct {
	baseData
	Error      string
	Domains    []string
	Values     map[string]string
	Strategies []string
}

func (s *Server) handleProjectNew(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.createProject(w, r)
		return
	}
	s.renderProjectForm(w, r, "", map[string]string{"strategy": "auto"})
}

func (s *Server) renderProjectForm(w http.ResponseWriter, r *http.Request, errMsg string, vals map[string]string) {
	s.render(w, "layout", projectFormData{
		baseData:   s.page(w, r, "New project", "projects", "project-form"),
		Error:      errMsg,
		Domains:    s.Store.Domains(),
		Values:     vals,
		Strategies: []string{"auto", "static", "dockerfile", "nixpacks"},
	})
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.Auth.CheckCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	vals := map[string]string{
		"name":        strings.TrimSpace(r.FormValue("name")),
		"source_path": strings.TrimSpace(r.FormValue("source_path")),
		"repo_url":    strings.TrimSpace(r.FormValue("repo_url")),
		"branch":      strings.TrimSpace(r.FormValue("branch")),
		"domain":      strings.TrimSpace(r.FormValue("domain")),
		"strategy":    r.FormValue("strategy"),
		"app_port":    r.FormValue("app_port"),
	}
	p := &store.Project{
		Name:       vals["name"],
		SourcePath: vals["source_path"],
		RepoURL:    vals["repo_url"],
		Branch:     vals["branch"],
		Domain:     vals["domain"],
		Strategy:   vals["strategy"],
	}
	p.AppPort, _ = strconv.Atoi(vals["app_port"])
	// Resolve "auto" now only for a local path we can inspect; for a Git
	// repo the strategy is detected after the first clone.
	if (p.Strategy == "" || p.Strategy == "auto") && p.SourcePath != "" && p.RepoURL == "" {
		info := deploy.DetectSource(p.SourcePath)
		p.Strategy = info.Strategy
		if p.AppPort == 0 {
			p.AppPort = info.AppPort
		}
	}
	if r.FormValue("spa") == "on" {
		p.RunCmd = "spa"
	}
	if p.Name == "" || p.Domain == "" || (p.SourcePath == "" && p.RepoURL == "") {
		s.renderProjectForm(w, r, "Name, domain, and either a source path or a Git repo URL are required.", vals)
		return
	}
	// Git projects get an encrypted token (private repos) + a webhook secret.
	if p.RepoURL != "" {
		if token := strings.TrimSpace(r.FormValue("token")); token != "" && s.Deploy.Secrets != nil {
			if enc, err := s.Deploy.Secrets.Encrypt(token); err == nil {
				p.TokenEnc = enc
			}
		}
		p.WebhookSecret = randHex(20)
	}
	if err := s.DB.CreateProject(p); err != nil {
		s.renderProjectForm(w, r, err.Error(), vals)
		return
	}
	s.audit(r, s.user(r), "project.create", p.Name, "ok")
	http.Redirect(w, r, "/projects/"+strconv.FormatInt(p.ID, 10), http.StatusSeeOther)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- item + actions ----

func (s *Server) handleProjectItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/projects/")
	parts := strings.SplitN(rest, "/", 2)
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	p, err := s.DB.GetProject(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if len(parts) == 2 {
		switch parts[1] {
		case "deploy":
			s.actionDeploy(w, r, p)
		case "stop":
			s.actionSimple(w, r, p, "project.stop", func(ctx context.Context) error { return s.Deploy.Stop(ctx, p.ID) }, "/projects/"+parts[0])
		case "remove":
			s.actionSimple(w, r, p, "project.remove", func(ctx context.Context) error { return s.Deploy.Remove(ctx, p.ID) }, "/projects")
		case "logs":
			s.projectLogs(w, r, p.ID)
		case "services":
			s.setProjectServices(w, r, p)
		case "env":
			s.setProjectEnv(w, r, p)
		default:
			http.NotFound(w, r)
		}
		return
	}
	s.projectDetail(w, r, p)
}

func (s *Server) setProjectServices(w http.ResponseWriter, r *http.Request, p *store.Project) {
	if !s.postCSRF(w, r) {
		return
	}
	var ids []int64
	for _, v := range r.Form["service"] {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	if err := s.DB.SetProjectServices(p.ID, ids); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, s.user(r), "project.services", p.Name, strconv.Itoa(len(ids)))
	http.Redirect(w, r, "/projects/"+strconv.FormatInt(p.ID, 10), http.StatusSeeOther)
}

func (s *Server) setProjectEnv(w http.ResponseWriter, r *http.Request, p *store.Project) {
	if !s.postCSRF(w, r) {
		return
	}
	kv := parseEnvText(r.FormValue("env"))
	enc := ""
	if len(kv) > 0 && s.Deploy.Secrets != nil {
		b, _ := json.Marshal(kv)
		enc, _ = s.Deploy.Secrets.Encrypt(string(b))
	}
	p.EnvEnc = enc
	if err := s.DB.UpdateProject(p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, s.user(r), "project.env", p.Name, strconv.Itoa(len(kv)))
	http.Redirect(w, r, "/projects/"+strconv.FormatInt(p.ID, 10), http.StatusSeeOther)
}

// parseEnvText turns "KEY=VALUE" lines into a map (skips blanks/#comments).
func parseEnvText(text string) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '='); i > 0 {
			kv[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
		}
	}
	return kv
}

// envText renders a project's stored env as sorted KEY=VALUE lines.
func (s *Server) envText(p *store.Project) string {
	if p.EnvEnc == "" || s.Deploy.Secrets == nil {
		return ""
	}
	dec, err := s.Deploy.Secrets.Decrypt(p.EnvEnc)
	if err != nil {
		return ""
	}
	var kv map[string]string
	if json.Unmarshal([]byte(dec), &kv) != nil {
		return ""
	}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + kv[k] + "\n")
	}
	return b.String()
}

func (s *Server) actionDeploy(w http.ResponseWriter, r *http.Request, p *store.Project) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.Auth.CheckCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	s.TriggerDeploy(p.ID)
	s.audit(r, s.user(r), "project.deploy", p.Name, "started")
	http.Redirect(w, r, "/projects/"+strconv.FormatInt(p.ID, 10), http.StatusSeeOther)
}

// TriggerDeploy starts an async deploy for a project (shared by the GUI
// deploy button and by push webhooks). No-op if one is already running.
func (s *Server) TriggerDeploy(id int64) {
	if s.isDeploying(id) {
		return
	}
	lb := s.logFor(id)
	lb.reset()
	io.WriteString(lb, "Starting deploy...\n")
	s.setDeploying(id, true)
	go func() {
		defer s.setDeploying(id, false)
		if err := s.Deploy.Deploy(context.Background(), id, lb); err != nil {
			io.WriteString(lb, "\n=== DEPLOY FAILED: "+err.Error()+" ===\n")
		} else {
			io.WriteString(lb, "\n=== DEPLOY OK ===\n")
		}
	}()
}

func (s *Server) actionSimple(w http.ResponseWriter, r *http.Request, p *store.Project, action string, fn func(context.Context) error, redirect string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.Auth.CheckCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	if err := fn(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, s.user(r), action, p.Name, "ok")
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

type projectDetailData struct {
	baseData
	Project     *store.Project
	Status      string
	Deploying   bool
	Deployment  *store.Deployment
	WebhookPath string // e.g. /_orxies/deploy/3 (git projects only)
	Services    []*store.Service
	Linked      map[int64]bool
	EnvText     string
}

func (s *Server) projectDetail(w http.ResponseWriter, r *http.Request, p *store.Project) {
	d, _ := s.DB.LatestDeployment(p.ID)
	status := "never deployed"
	if d != nil {
		status = d.Status
	}
	wh := ""
	if p.RepoURL != "" {
		wh = webhook.PathPrefix + strconv.FormatInt(p.ID, 10)
	}
	allSvcs, _ := s.DB.ListServices()
	linked := map[int64]bool{}
	if ls, err := s.DB.LinkedServices(p.ID); err == nil {
		for _, sv := range ls {
			linked[sv.ID] = true
		}
	}
	s.render(w, "layout", projectDetailData{
		baseData:    s.page(w, r, p.Name, "projects", "project-detail"),
		Project:     p,
		Status:      status,
		Deploying:   s.isDeploying(p.ID),
		Deployment:  d,
		WebhookPath: wh,
		Services:    allSvcs,
		Linked:      linked,
		EnvText:     s.envText(p),
	})
}

// projectLogs returns the current deploy log (HTML-escaped) for polling.
func (s *Server) projectLogs(w http.ResponseWriter, r *http.Request, id int64) {
	out := s.logFor(id).String()
	// Append recent container logs when a deployment is live and idle.
	if !s.isDeploying(id) {
		if d, err := s.DB.LatestDeployment(id); err == nil && d.ContainerID != "" {
			var cb bytes.Buffer
			if err := s.Deploy.Logs(r.Context(), int(id), 100, &cb); err == nil && cb.Len() > 0 {
				out += "\n--- container logs ---\n" + cb.String()
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	io.WriteString(w, string(template.HTMLEscapeString(out)))
}
