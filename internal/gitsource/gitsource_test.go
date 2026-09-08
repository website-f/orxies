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
	// Re-sync must be idempotent.
	if _, err := Sync(context.Background(), src, "", "", dest); err != nil {
		t.Errorf("re-Sync: %v", err)
	}
}

// commit adds a file to an existing repo and returns the new HEAD.
func commit(t *testing.T, dir, name, body string) string {
	t.Helper()
	repo, err := git.PlainOpen(dir)
	if err != nil {
		t.Fatal(err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add(name); err != nil {
		t.Fatal(err)
	}
	h, err := wt.Commit("add "+name, &git.CommitOptions{
		Author: &object.Signature{Name: "t", Email: "t@example.com", When: time.Unix(1700000100, 0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h.String()
}

// A second Sync must pick up commits pushed after the first one — the
// "update an already-deployed project" path.
func TestSyncPullsNewCommits(t *testing.T) {
	src, firstSHA := makeRepo(t)
	dest := filepath.Join(t.TempDir(), "checkout")

	if _, err := SyncResult(context.Background(), src, "", "", dest); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	newSHA := commit(t, src, "index.html", "<h1>v2</h1>")

	res, err := SyncResult(context.Background(), src, "", "", dest)
	if err != nil {
		t.Fatalf("update sync: %v", err)
	}
	if res.SHA != newSHA {
		t.Errorf("SHA = %s, want %s (new commit not pulled)", res.SHA, newSHA)
	}
	if res.PrevSHA != firstSHA {
		t.Errorf("PrevSHA = %s, want %s", res.PrevSHA, firstSHA)
	}
	if !res.Changed() {
		t.Error("Changed() = false after a new upstream commit")
	}
	if res.Cloned {
		t.Error("Cloned = true; an existing checkout of the same remote should fetch, not re-clone")
	}
	if b, err := os.ReadFile(filepath.Join(dest, "index.html")); err != nil || string(b) != "<h1>v2</h1>" {
		t.Errorf("new file not in working tree: %q %v", b, err)
	}
}

// With nothing new upstream, a sync reports no change but still leaves a
// complete working tree behind.
func TestSyncNoChangeKeepsTree(t *testing.T) {
	src, sha := makeRepo(t)
	dest := filepath.Join(t.TempDir(), "checkout")
	if _, err := SyncResult(context.Background(), src, "", "", dest); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	res, err := SyncResult(context.Background(), src, "", "", dest)
	if err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if res.SHA != sha {
		t.Errorf("SHA = %s, want %s", res.SHA, sha)
	}
	if res.Changed() {
		t.Error("Changed() = true with no new commits")
	}
	if _, err := os.Stat(filepath.Join(dest, "Dockerfile")); err != nil {
		t.Errorf("working tree incomplete after no-op sync: %v", err)
	}
}

// Files deleted upstream must disappear from the checkout, or a static
// site would keep serving pages the author removed.
func TestSyncDropsFilesDeletedUpstream(t *testing.T) {
	src, _ := makeRepo(t)
	commit(t, src, "old.html", "gone soon")
	dest := filepath.Join(t.TempDir(), "checkout")
	if _, err := Sync(context.Background(), src, "", "", dest); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "old.html")); err != nil {
		t.Fatalf("setup: old.html not checked out: %v", err)
	}

	repo, err := git.PlainOpen(src)
	if err != nil {
		t.Fatal(err)
	}
	wt, _ := repo.Worktree()
	if _, err := wt.Remove("old.html"); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Commit("drop old.html", &git.CommitOptions{
		Author: &object.Signature{Name: "t", Email: "t@example.com", When: time.Unix(1700000200, 0)},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := Sync(context.Background(), src, "", "", dest); err != nil {
		t.Fatalf("update sync: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "old.html")); !os.IsNotExist(err) {
		t.Errorf("old.html still present after upstream deletion (err=%v)", err)
	}
}

// A checkout pointing at a different remote is replaced wholesale rather
// than fetched into.
func TestSyncReplacesCheckoutOfADifferentRepo(t *testing.T) {
	repoA, _ := makeRepo(t)
	repoB, shaB := makeRepo(t)
	commit(t, repoB, "b.txt", "from B")
	shaB = commit(t, repoB, "b2.txt", "from B again")

	dest := filepath.Join(t.TempDir(), "checkout")
	if _, err := Sync(context.Background(), repoA, "", "", dest); err != nil {
		t.Fatalf("sync A: %v", err)
	}
	res, err := SyncResult(context.Background(), repoB, "", "", dest)
	if err != nil {
		t.Fatalf("sync B: %v", err)
	}
	if res.SHA != shaB {
		t.Errorf("SHA = %s, want %s", res.SHA, shaB)
	}
	if !res.Cloned {
		t.Error("Cloned = false; a different remote must trigger a fresh clone")
	}
	if _, err := os.Stat(filepath.Join(dest, "b2.txt")); err != nil {
		t.Errorf("repo B content missing: %v", err)
	}
}

// A failed sync must leave the previous checkout serving, not delete it.
func TestSyncFailureLeavesExistingCheckoutIntact(t *testing.T) {
	src, sha := makeRepo(t)
	dest := filepath.Join(t.TempDir(), "checkout")
	if _, err := Sync(context.Background(), src, "", "", dest); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if _, err := SyncResult(context.Background(), filepath.Join(t.TempDir(), "nope"), "", "", dest); err == nil {
		t.Fatal("expected an error syncing a nonexistent repo")
	}
	if _, err := os.Stat(filepath.Join(dest, "Dockerfile")); err != nil {
		t.Errorf("previous checkout destroyed by a failed sync: %v", err)
	}
	repo, err := git.PlainOpen(dest)
	if err != nil {
		t.Fatalf("checkout no longer a repo: %v", err)
	}
	if h, _ := repo.Head(); h == nil || h.Hash().String() != sha {
		t.Errorf("HEAD moved after a failed sync, want %s", sha)
	}
}
