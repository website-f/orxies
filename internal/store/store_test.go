package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreCRUDAndPorts(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Projects
	p := &Project{Name: "blog", SourcePath: "/srv/blog", Strategy: "static", Domain: "blog.test"}
	if err := db.CreateProject(p); err != nil {
		t.Fatal(err)
	}
	if p.ID == 0 {
		t.Fatal("CreateProject did not set ID")
	}
	got, err := db.GetProject(p.ID)
	if err != nil || got.Name != "blog" || got.Domain != "blog.test" {
		t.Fatalf("GetProject: %v %+v", err, got)
	}
	if byName, err := db.ProjectByName("blog"); err != nil || byName.ID != p.ID {
		t.Fatalf("ProjectByName: %v", err)
	}
	if err := db.CreateProject(&Project{Name: "blog", SourcePath: "x", Strategy: "static"}); err == nil {
		t.Error("expected UNIQUE(name) violation on duplicate project")
	}

	// Deployments
	d := &Deployment{ProjectID: p.ID, Status: StatusBuilding}
	if err := db.CreateDeployment(d); err != nil {
		t.Fatal(err)
	}
	d.Status, d.ContainerID, d.HostPort = StatusRunning, "abc123", 8301
	now := time.Now().UTC()
	d.FinishedAt = &now
	if err := db.UpdateDeployment(d); err != nil {
		t.Fatal(err)
	}
	latest, err := db.LatestDeployment(p.ID)
	if err != nil || latest.Status != StatusRunning || latest.HostPort != 8301 || latest.FinishedAt == nil {
		t.Fatalf("LatestDeployment: %v %+v", err, latest)
	}

	// Port allocator: lowest-free, release, reuse
	if port, err := db.AllocatePort(d.ID, 8300, 8302); err != nil || port != 8300 {
		t.Fatalf("AllocatePort#1 = %d, %v (want 8300)", port, err)
	}
	if port, _ := db.AllocatePort(d.ID, 8300, 8302); port != 8301 {
		t.Fatalf("AllocatePort#2 = %d (want 8301)", port)
	}
	if err := db.ReleasePort(8300); err != nil {
		t.Fatal(err)
	}
	if port, _ := db.AllocatePort(d.ID, 8300, 8302); port != 8300 {
		t.Fatalf("AllocatePort#3 = %d (want reuse of 8300)", port)
	}
	// Exhaust the range
	db.AllocatePort(d.ID, 8300, 8302) // 8302
	if _, err := db.AllocatePort(d.ID, 8300, 8302); !errors.Is(err, ErrNoFreePort) {
		t.Errorf("expected ErrNoFreePort when range exhausted, got %v", err)
	}

	// Cascade delete
	if err := db.DeleteProject(p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetProject(p.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetProject after delete = %v, want ErrNotFound", err)
	}
	if _, err := db.LatestDeployment(p.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deployments should cascade-delete, got %v", err)
	}
}
