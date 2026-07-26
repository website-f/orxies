package gitsource

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func makeRepo(t *testing.T) (dir, sha string) {
	t.Helper()
	dir = t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add("Dockerfile"); err != nil {
		t.Fatal(err)
	}
	h, err := wt.Commit("init", &git.CommitOptions{
		Author: &object.Signature{Name: "t", Email: "t@example.com", When: time.Unix(1700000000, 0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return dir, h.String()
}

func TestSyncClonesLocalRepo(t *testing.T) {
	src, wantSHA := makeRepo(t)
	dest := filepath.Join(t.TempDir(), "checkout")

	sha, err := Sync(context.Background(), src, "", "", dest)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if sha != wantSHA {
		t.Errorf("SHA = %s, want %s", sha, wantSHA)
	}
	if _, err := os.Stat(filepath.Join(dest, "Dockerfile")); err != nil {
		t.Errorf("Dockerfile not checked out: %v", err)
	}
	// Re-sync must be idempotent (wipes + re-clones).
	if _, err := Sync(context.Background(), src, "", "", dest); err != nil {
		t.Errorf("re-Sync: %v", err)
	}
}
