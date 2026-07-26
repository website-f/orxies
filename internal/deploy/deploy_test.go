package deploy

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"orxies/internal/agent"
	"orxies/internal/config"
	"orxies/internal/store"
)

// fakeAgent implements Orchestrator. Run opens a real loopback listener
// on the requested port so the manager's TCP health check passes without
// Docker; Remove closes it.
type fakeAgent struct {
	mu      sync.Mutex
	lns     map[string]net.Listener
	built   []string
	removed []string
}

func newFakeAgent() *fakeAgent { return &fakeAgent{lns: map[string]net.Listener{}} }

func (f *fakeAgent) Build(_ context.Context, spec agent.BuildSpec, w io.Writer) error {
	io.WriteString(w, "building "+spec.Name+"\n")
	f.mu.Lock()
	f.built = append(f.built, spec.Name)
	f.mu.Unlock()
	return nil
}
func (f *fakeAgent) Run(_ context.Context, spec agent.RunSpec) (string, error) {
	// App containers publish to a host port (health-checked); service
	// containers (HostPort 0) don't — just record them.
	if spec.HostPort > 0 {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", spec.HostPort))
		if err != nil {
			return "", err
		}
		f.mu.Lock()
		f.lns[spec.Name] = ln
		f.mu.Unlock()
	}
	return "cid-" + spec.Name, nil
}
func (f *fakeAgent) EnsureNetwork(_ context.Context, _ string) error { return nil }
func (f *fakeAgent) Stop(_ context.Context, _ string) error { return nil }
func (f *fakeAgent) Remove(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, id)
	for name, ln := range f.lns {
		if "cid-"+name == id {
			ln.Close()
			delete(f.lns, name)
		}
	}
	return nil
}
func (f *fakeAgent) Logs(_ context.Context, _ string, _ int, w io.Writer) error {
	io.WriteString(w, "logs\n")
	return nil
}
func (f *fakeAgent) Status(_ context.Context, _ string) (agent.Status, error) {
	return agent.Status{State: "running", Running: true}, nil
}
func (f *fakeAgent) closeAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ln := range f.lns {
		ln.Close()
	}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestDetect(t *testing.T) {
	dir := t.TempDir()
	if got := Detect(dir); got != "nixpacks" {
		t.Errorf("empty dir → %s, want nixpacks", got)
	}
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("x"), 0o644)
	if got := Detect(dir); got != "static" {
		t.Errorf("html-only → %s, want static", got)
	}
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch"), 0o644)
	if got := Detect(dir); got != "dockerfile" {
		t.Errorf("Dockerfile present → %s, want dockerfile", got)
	}
}

func TestDetectSource(t *testing.T) {
	cases := []struct {
		files map[string]string
		want  string // strategy
	}{
		{map[string]string{"Dockerfile": "FROM scratch"}, "dockerfile"},
		{map[string]string{"package.json": `{"dependencies":{"next":"14"}}`}, "nixpacks"},
		{map[string]string{"requirements.txt": "flask"}, "nixpacks"},
		{map[string]string{"go.mod": "module x"}, "nixpacks"},
		{map[string]string{"index.html": "<h1>hi</h1>"}, "static"},
		{map[string]string{"wp-config.php": "<?php"}, "nixpacks"},
	}
	for i, c := range cases {
		dir := t.TempDir()
		for f, body := range c.files {
			os.WriteFile(filepath.Join(dir, f), []byte(body), 0o644)
		}
		if got := DetectSource(dir); got.Strategy != c.want {
			t.Errorf("case %d: strategy=%s want %s (framework=%s)", i, got.Strategy, c.want, got.Framework)
		}
	}
	// Framework label sanity.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"next":"14"}}`), 0o644)
	if fw := DetectSource(dir).Framework; fw != "Next.js" {
		t.Errorf("framework=%s, want Next.js", fw)
	}
}

// makeGitRepo creates a local git repo containing a Dockerfile and
// returns its path + HEAD SHA.
func makeGitRepo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	wt, _ := repo.Worktree()
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o644)
	wt.Add("Dockerfile")
	h, err := wt.Commit("init", &git.CommitOptions{
		Author: &object.Signature{Name: "t", Email: "t@example.com", When: time.Unix(1700000000, 0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return dir, h.String()
}

func TestDeployFromGitRepo(t *testing.T) {
	db := openStore(t)
	repoDir, wantSHA := makeGitRepo(t)
	sites := t.TempDir()
	fa := newFakeAgent()
	defer fa.closeAll()
	m := &Manager{Store: db, Agent: fa, SitesDir: sites, ReposDir: t.TempDir(), OnChange: func() {}}

	// strategy "auto" → detected from the cloned tree (Dockerfile → dockerfile)
	p := &store.Project{Name: "gitapp", RepoURL: repoDir, Strategy: "auto", Domain: "git.test", AppPort: 80}
	if err := db.CreateProject(p); err != nil {
		t.Fatal(err)
	}
	if err := m.Deploy(context.Background(), p.ID, io.Discard); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	dep, _ := db.LatestDeployment(p.ID)
	if dep.Status != store.StatusRunning {
		t.Fatalf("status=%s, want running", dep.Status)
	}
	if dep.CommitSHA != wantSHA {
		t.Errorf("commit=%s, want %s", dep.CommitSHA, wantSHA)
	}
	// strategy resolved + persisted
	if got, _ := db.GetProject(p.ID); got.Strategy != "dockerfile" {
		t.Errorf("strategy=%s, want dockerfile (auto-detected post-clone)", got.Strategy)
	}
	// route written
	if _, err := os.Stat(filepath.Join(sites, config.SiteFilename("git.test"))); err != nil {
		t.Errorf("site file not written: %v", err)
	}
}

func TestDeployStatic(t *testing.T) {
	db := openStore(t)
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "index.html"), []byte("<h1>hi</h1>"), 0o644)
	sites := t.TempDir()
	reloaded := 0
	m := &Manager{Store: db, SitesDir: sites, OnChange: func() { reloaded++ }}

	p := &store.Project{Name: "blog", SourcePath: src, Strategy: "static", Domain: "blog.test"}
	if err := db.CreateProject(p); err != nil {
		t.Fatal(err)
	}
	if err := m.Deploy(context.Background(), p.ID, io.Discard); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sites, config.SiteFilename("blog.test"))); err != nil {
		t.Fatalf("static site file not written: %v", err)
	}
	if dep, _ := db.LatestDeployment(p.ID); dep.Status != store.StatusRunning {
		t.Errorf("status=%s, want running", dep.Status)
	}
	if reloaded == 0 {
		t.Error("OnChange (reload) not triggered")
	}
}

func TestDeployContainerAndRedeploy(t *testing.T) {
	db := openStore(t)
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "Dockerfile"), []byte("FROM scratch"), 0o644)
	sites := t.TempDir()
	fa := newFakeAgent()
	defer fa.closeAll()
	m := &Manager{Store: db, Agent: fa, SitesDir: sites, OnChange: func() {}}

	p := &store.Project{Name: "api", SourcePath: src, Strategy: "dockerfile", Domain: "api.test", AppPort: 80}
	if err := db.CreateProject(p); err != nil {
		t.Fatal(err)
	}

	if err := m.Deploy(context.Background(), p.ID, io.Discard); err != nil {
		t.Fatalf("deploy#1: %v", err)
	}
	d1, _ := db.LatestDeployment(p.ID)
	if d1.Status != store.StatusRunning || d1.HostPort == 0 || d1.ContainerID == "" {
		t.Fatalf("deploy#1 result: %+v", d1)
	}

	if err := m.Deploy(context.Background(), p.ID, io.Discard); err != nil {
		t.Fatalf("deploy#2 (redeploy): %v", err)
	}
	d2, _ := db.LatestDeployment(p.ID)
	if d2.ID == d1.ID {
		t.Fatal("redeploy did not create a new deployment")
	}
	if d2.HostPort == d1.HostPort {
		t.Errorf("redeploy reused port %d; expected a new one (zero-downtime)", d1.HostPort)
	}
	drained := false
	for _, r := range fa.removed {
		if r == d1.ContainerID {
			drained = true
		}
	}
	if !drained {
		t.Errorf("old container %q not drained; removed=%v", d1.ContainerID, fa.removed)
	}

	if err := m.Stop(context.Background(), p.ID); err != nil {
		t.Fatal(err)
	}
	if dep, _ := db.LatestDeployment(p.ID); dep.Status != store.StatusStopped {
		t.Errorf("after Stop status=%s, want stopped", dep.Status)
	}
}
