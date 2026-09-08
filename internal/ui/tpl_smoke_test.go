package ui

import (
	"bytes"
	"testing"
	"time"

	"orxies/internal/deploy"
	"orxies/internal/store"
)

// Renders service-detail with a backup row so template funcs (icon, bytes)
// and the Backups section are exercised end-to-end.
func TestServiceDetailBackupTemplate(t *testing.T) {
	s, err := New(&Server{})
	if err != nil {
		t.Fatal(err)
	}
	type data struct {
		baseData
		Service   *store.Service
		Host      string
		Busy      bool
		Backups   []deploy.Backup
		BackupsOK bool
	}
	d := data{
		Service:   &store.Service{ID: 1, Name: "pg", Engine: "postgres", Mode: "managed", Status: "running"},
		Host:      "orxies-svc-pg",
		BackupsOK: true,
		Backups:   []deploy.Backup{{Name: "20260728-101500.sql", Size: 4096, ModTime: time.Now()}},
	}
	var buf bytes.Buffer
	if err := s.tpl.ExecuteTemplate(&buf, "service-detail", d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Back up now", "20260728-101500.sql", "4.0 KB", "Restore", "backup-download"} {
		if !bytes.Contains(buf.Bytes(), []byte(want)) {
			t.Errorf("rendered output missing %q", want)
		}
	}
}

// The Update button is the entry point for pulling a project's latest
// commit, so it must appear for git-backed projects — and must not
// appear for folder-backed ones, where there is nothing to pull.
func TestProjectTemplatesUpdateButton(t *testing.T) {
	s, err := New(&Server{})
	if err != nil {
		t.Fatal(err)
	}
	type detailData struct {
		baseData
		Project     *store.Project
		Status      string
		Deploying   bool
		Deployment  *store.Deployment
		WebhookPath string
		Services    []*store.Service
		Linked      map[int64]bool
		EnvText     string
		Deployments []*store.Deployment
		CurrentID   int64
	}
	type listData struct {
		baseData
		Projects []projectRow
	}

	git := &store.Project{ID: 7, Name: "site", Domain: "site.test", Strategy: "static",
		RepoURL: "https://github.com/me/site.git", Branch: "main"}
	local := &store.Project{ID: 8, Name: "folder", Domain: "folder.test", Strategy: "static",
		SourcePath: "/srv/folder"}

	render := func(name string, data any) string {
		t.Helper()
		var buf bytes.Buffer
		if err := s.tpl.ExecuteTemplate(&buf, name, data); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return buf.String()
	}

	out := render("project-detail", detailData{
		Project:    git,
		Status:     "running",
		Deployment: &store.Deployment{ID: 3, CommitSHA: "abcdef1234567890", Status: "running"},
		Linked:     map[int64]bool{},
	})
	for _, want := range []string{"/projects/7/update", "Update (pull latest)", "Full redeploy", "abcdef12", "main"} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("git project detail missing %q", want)
		}
	}

	out = render("project-detail", detailData{Project: local, Status: "running", Linked: map[int64]bool{}})
	if bytes.Contains([]byte(out), []byte("/projects/8/update")) {
		t.Error("folder-backed project offered an Update button with nothing to pull")
	}
	if !bytes.Contains([]byte(out), []byte("/projects/8/deploy")) {
		t.Error("folder-backed project lost its Deploy button")
	}

	out = render("projects", listData{Projects: []projectRow{
		{Project: git, Status: "running"},
		{Project: local, Status: "running"},
	}})
	if !bytes.Contains([]byte(out), []byte("/projects/7/update")) {
		t.Error("projects list missing the Update action for a git project")
	}
	if bytes.Contains([]byte(out), []byte("/projects/8/update")) {
		t.Error("projects list offered Update for a folder-backed project")
	}
}
