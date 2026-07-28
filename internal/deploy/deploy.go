// Package deploy is the control-plane orchestrator: it turns a Project
// into a live site by driving the agent (build + run a container) or, for
// static projects, by pointing the edge straight at a folder. It then
// registers/updates the proxy (or static) site the existing router
// already knows how to serve.
package deploy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"orxies/internal/agent"
	"orxies/internal/config"
	"orxies/internal/gitsource"
	"orxies/internal/secretbox"
	"orxies/internal/store"
)

const defaultAppPort = 3000

// Orchestrator is the subset of the agent the manager needs (an
// interface so tests can fake it).
type Orchestrator interface {
	Build(context.Context, agent.BuildSpec, io.Writer) error
	Run(context.Context, agent.RunSpec) (string, error)
	Stop(context.Context, string) error
	Remove(context.Context, string) error
	Logs(context.Context, string, int, io.Writer) error
	Status(context.Context, string) (agent.Status, error)
	EnsureNetwork(context.Context, string) error
	ExecOut(context.Context, agent.ExecSpec, io.Writer) error
	ExecIn(context.Context, agent.ExecSpec, io.Reader) error
}

// NetworkName is the shared docker network apps + managed services join so
// an app can reach its database by the service's container name.
const NetworkName = "orxies-net"

// Manager orchestrates deployments.
type Manager struct {
	Store      *store.Store
	Agent      Orchestrator // nil → only static projects can deploy
	SitesDir   string
	ReposDir   string         // where git-backed projects are checked out
	BackupsDir string         // where managed-service dumps are stored
	Secrets    *secretbox.Box // decrypts per-project access tokens
	OnChange   func()         // called after a site file is written, to hot-reload routing
}

// DetectInfo is what orxies inferred about a source tree.
type DetectInfo struct {
	Strategy  string // "dockerfile" | "static" | "nixpacks"
	Framework string // human-readable label for the GUI
	AppPort   int    // suggested container port (0 = let the image/EXPOSE decide)
	SPA       bool   // for static: serve index.html on unmatched paths
}

// DetectSource classifies a source directory. Precedence: an explicit
// Dockerfile always wins; a folder of plain static assets is served
// directly; everything else builds with Nixpacks, with a best-effort
// framework label read from the project's manifest.
func DetectSource(path string) DetectInfo {
	has := func(f string) bool { return fileExists(filepath.Join(path, f)) }
	hasDir := func(d string) bool { return dirExists(filepath.Join(path, d)) }

	switch {
	case has("Dockerfile"):
		return DetectInfo{Strategy: "dockerfile", Framework: "Dockerfile"}
	case has("docker-compose.yml") || has("compose.yaml") || has("compose.yml"):
		return DetectInfo{Strategy: "dockerfile", Framework: "docker-compose"}
	case has("wp-config.php") || has("wp-login.php") || hasDir("wp-content"):
		return DetectInfo{Strategy: "nixpacks", Framework: "WordPress (PHP)", AppPort: 80}
	case has("composer.json") || anyFileWithExt(path, ".php"):
		return DetectInfo{Strategy: "nixpacks", Framework: "PHP", AppPort: 80}
	case has("package.json"):
		fw := jsFramework(filepath.Join(path, "package.json"))
		return DetectInfo{Strategy: "nixpacks", Framework: fw, AppPort: 3000}
	case has("requirements.txt") || has("pyproject.toml") || has("Pipfile"):
		return DetectInfo{Strategy: "nixpacks", Framework: "Python", AppPort: 8000}
	case has("go.mod"):
		return DetectInfo{Strategy: "nixpacks", Framework: "Go", AppPort: 3000}
	case has("Gemfile"):
		return DetectInfo{Strategy: "nixpacks", Framework: "Ruby", AppPort: 3000}
	case has("index.html"):
		return DetectInfo{Strategy: "static", Framework: "Static site"}
	default:
		return DetectInfo{Strategy: "nixpacks", Framework: "generic"}
	}
}

// Detect returns just the build strategy (kept for callers that only
// need the bucket).
func Detect(path string) string { return DetectSource(path).Strategy }

// jsFramework reads package.json dependencies for a friendly label.
func jsFramework(pkgPath string) string {
	b, err := os.ReadFile(pkgPath)
	if err != nil {
		return "Node.js"
	}
	s := string(b)
	switch {
	case contains(s, `"next"`):
		return "Next.js"
	case contains(s, `"nuxt"`):
		return "Nuxt"
	case contains(s, `"@angular/core"`):
		return "Angular"
	case contains(s, `"vue"`):
		return "Vue"
	case contains(s, `"vite"`), contains(s, `"react"`):
		return "React/Vite"
	default:
		return "Node.js"
	}
}

func contains(hay, needle string) bool { return strings.Contains(hay, needle) }

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func anyFileWithExt(dir, ext string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ext) {
			return true
		}
	}
	return false
}

// Deploy performs a full (optionally git-sourced) build+run+route for a
// project, streaming output to logW. Blocking. Zero-downtime: the new
// container is built, run, and health-checked before the route flips and
// the old one drains.
func (m *Manager) Deploy(ctx context.Context, projectID int64, logW io.Writer) error {
	p, err := m.Store.GetProject(projectID)
	if err != nil {
		return err
	}
	dep := &store.Deployment{ProjectID: p.ID, Status: store.StatusBuilding}
	if err := m.Store.CreateDeployment(dep); err != nil {
		return err
	}

	// Git-backed projects: (re)clone into ReposDir and build from there.
	src := p.SourcePath
	if p.RepoURL != "" {
		token := ""
		if p.TokenEnc != "" && m.Secrets != nil {
			if t, derr := m.Secrets.Decrypt(p.TokenEnc); derr == nil {
				token = t
			}
		}
		dir := filepath.Join(m.ReposDir, safeName(p.Name))
		branch := p.Branch
		if branch == "" {
			branch = "default branch"
		}
		fmt.Fprintf(logW, "Cloning %s (%s)...\n", p.RepoURL, branch)
		sha, gerr := gitsource.Sync(ctx, p.RepoURL, p.Branch, token, dir)
		if gerr != nil {
			return m.fail(dep, fmt.Errorf("git clone: %w", gerr))
		}
		dep.CommitSHA = sha
		src = dir
		short := sha
		if len(short) > 8 {
			short = short[:8]
		}
		fmt.Fprintf(logW, "Checked out %s\n", short)
	}

	// Resolve an as-yet-undetected strategy now that we have the source.
	if p.Strategy == "" || p.Strategy == "auto" {
		info := DetectSource(src)
		p.Strategy = info.Strategy
		if p.AppPort == 0 {
			p.AppPort = info.AppPort
		}
		fmt.Fprintf(logW, "Detected %s → %s build\n", info.Framework, p.Strategy)
		_ = m.Store.UpdateProject(p)
	}

	if p.Strategy == "static" {
		return m.finishStatic(p, dep, src)
	}
	return m.finishContainer(ctx, p, dep, src, logW)
}

func (m *Manager) finishStatic(p *store.Project, dep *store.Deployment, src string) error {
	site := &config.Site{
		Domain:  p.Domain,
		Enabled: true,
		Root:    src,
		SPA:     p.RunCmd == "spa", // RunCmd doubles as the SPA flag for static sites
		TLS:     config.TLSConfig{Auto: false},
	}
	if _, err := config.SaveSite(m.SitesDir, site); err != nil {
		return m.fail(dep, err)
	}
	m.reload()
	return m.succeed(dep)
}

func (m *Manager) finishContainer(ctx context.Context, p *store.Project, dep *store.Deployment, src string, logW io.Writer) error {
	if m.Agent == nil {
		return m.fail(dep, errors.New("agent not configured — container projects need the orxies-agent"))
	}
	image := fmt.Sprintf("orxies/%s:%d", p.Name, dep.ID)
	if err := m.Agent.Build(ctx, agent.BuildSpec{
		Name:       image,
		SourcePath: src,
		Strategy:   p.Strategy,
	}, logW); err != nil {
		return m.fail(dep, fmt.Errorf("build: %w", err))
	}
	dep.ImageRef = image
	return m.runImage(ctx, p, dep, image, logW)
}

// runImage starts an already-built image as the project's new container,
// health-checks it, flips the route, and drains older containers. Shared
// by first-time deploy and rollback (which skips the build).
func (m *Manager) runImage(ctx context.Context, p *store.Project, dep *store.Deployment, image string, logW io.Writer) error {
	name := fmt.Sprintf("orxies-%s-%d", p.Name, dep.ID)
	port, err := m.Store.AllocatePort(dep.ID, store.PortRangeLo, store.PortRangeHi)
	if err != nil {
		return m.fail(dep, err)
	}
	appPort := p.AppPort
	if appPort == 0 {
		appPort = defaultAppPort
	}
	// Join the shared network (so linked DBs are reachable by name) and
	// assemble env: PORT + injected service creds + custom project vars.
	_ = m.Agent.EnsureNetwork(ctx, NetworkName)
	env := m.envForProject(p, logW)
	env["PORT"] = strconv.Itoa(appPort)
	id, err := m.Agent.Run(ctx, agent.RunSpec{
		Name:     name,
		Image:    image,
		HostPort: port,
		AppPort:  appPort,
		Env:      env,
		MemoryMB: 512,
		Network:  NetworkName,
	})
	if err != nil {
		_ = m.Store.ReleasePort(port)
		return m.fail(dep, fmt.Errorf("run: %w", err))
	}
	dep.ContainerID, dep.HostPort, dep.ImageRef = id, port, image

	if err := waitHealthy(ctx, port, 30*time.Second); err != nil {
		// Leave the container so its logs are inspectable; mark failed.
		return m.fail(dep, fmt.Errorf("health check: %w", err))
	}

	// Flip the route to the new container, then drain older ones.
	site := &config.Site{
		Domain:    p.Domain,
		Enabled:   true,
		Upstreams: []string{fmt.Sprintf("127.0.0.1:%d", port)},
		WebSocket: true,
		TLS:       config.TLSConfig{Auto: false},
	}
	if _, err := config.SaveSite(m.SitesDir, site); err != nil {
		return m.fail(dep, err)
	}
	m.reload()
	m.drainOld(ctx, p.ID, dep.ID)
	return m.succeed(dep)
}

// Rollback re-runs a previous deployment's image (no rebuild) as a fresh
// deployment, then drains the current one — zero-downtime, like a deploy.
func (m *Manager) Rollback(ctx context.Context, projectID, deploymentID int64, logW io.Writer) error {
	p, err := m.Store.GetProject(projectID)
	if err != nil {
		return err
	}
	if m.Agent == nil {
		return errors.New("agent not configured")
	}
	target, err := m.Store.GetDeployment(deploymentID)
	if err != nil {
		return err
	}
	if target.ProjectID != projectID || target.ImageRef == "" {
		return errors.New("that deployment has no image to roll back to")
	}
	dep := &store.Deployment{ProjectID: p.ID, Status: store.StatusBuilding, CommitSHA: target.CommitSHA}
	if err := m.Store.CreateDeployment(dep); err != nil {
		return err
	}
	fmt.Fprintf(logW, "Rolling back to deployment #%d (image %s)...\n", target.ID, target.ImageRef)
	return m.runImage(ctx, p, dep, target.ImageRef, logW)
}

// Stop stops the project's current container (static projects: no-op).
func (m *Manager) Stop(ctx context.Context, projectID int64) error {
	dep, err := m.Store.LatestDeployment(projectID)
	if err != nil {
		return err
	}
	if dep.ContainerID != "" && m.Agent != nil {
		if err := m.Agent.Stop(ctx, dep.ContainerID); err != nil {
			return err
		}
	}
	dep.Status = store.StatusStopped
	return m.Store.UpdateDeployment(dep)
}

// Remove tears a project down: stop+remove its container, free its port,
// delete its site file, and delete the project row.
func (m *Manager) Remove(ctx context.Context, projectID int64) error {
	p, err := m.Store.GetProject(projectID)
	if err != nil {
		return err
	}
	if dep, err := m.Store.LatestDeployment(projectID); err == nil {
		if dep.ContainerID != "" && m.Agent != nil {
			_ = m.Agent.Remove(ctx, dep.ContainerID)
		}
		if dep.HostPort != 0 {
			_ = m.Store.ReleasePort(dep.HostPort)
		}
	}
	if p.Domain != "" {
		_ = config.DeleteSite(m.SitesDir, config.SiteFilename(p.Domain))
		m.reload()
	}
	return m.Store.DeleteProject(projectID)
}

// Logs streams up to tail lines of the current container's logs.
func (m *Manager) Logs(ctx context.Context, projectID, tail int, w io.Writer) error {
	dep, err := m.Store.LatestDeployment(int64(projectID))
	if err != nil {
		return err
	}
	if dep.ContainerID == "" || m.Agent == nil {
		return nil
	}
	return m.Agent.Logs(ctx, dep.ContainerID, tail, w)
}

func (m *Manager) drainOld(ctx context.Context, projectID, keepID int64) {
	deps, err := m.Store.ListDeployments(projectID)
	if err != nil {
		return
	}
	for _, d := range deps {
		if d.ID == keepID || d.ContainerID == "" || d.Status == store.StatusStopped {
			continue
		}
		if m.Agent != nil {
			_ = m.Agent.Remove(ctx, d.ContainerID)
		}
		if d.HostPort != 0 {
			_ = m.Store.ReleasePort(d.HostPort)
		}
		d.Status = store.StatusStopped
		_ = m.Store.UpdateDeployment(d)
	}
}

func (m *Manager) fail(dep *store.Deployment, err error) error {
	now := time.Now().UTC()
	dep.Status, dep.FinishedAt = store.StatusFailed, &now
	_ = m.Store.UpdateDeployment(dep)
	return err
}

func (m *Manager) succeed(dep *store.Deployment) error {
	now := time.Now().UTC()
	dep.Status, dep.FinishedAt = store.StatusRunning, &now
	return m.Store.UpdateDeployment(dep)
}

func (m *Manager) reload() {
	if m.OnChange != nil {
		m.OnChange()
	}
}

// waitHealthy polls a TCP dial to the container's published loopback
// port until it accepts a connection or the deadline passes.
func waitHealthy(ctx context.Context, port int, timeout time.Duration) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("port %d never became reachable", port)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// safeName sanitizes a project name into a single safe path component.
func safeName(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if s := string(out); s != "" {
		return s
	}
	return "_"
}
