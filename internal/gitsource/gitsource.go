// Package gitsource clones and updates a project's Git repository so the
// deploy engine can build (or directly serve) a working tree. It uses
// go-git (pure Go — no external `git` binary, keeps the CGO-free build).
//
// Sync is incremental where it can be: an existing checkout of the same
// remote is fetched and hard-reset onto the tracked branch — the "git
// pull" path — which is fast and, crucially, never leaves the working
// tree missing. That matters for static projects, whose live document
// root IS this directory: wiping it mid-update would 404 the site.
//
// When there is no usable checkout (first deploy, a changed remote, a
// corrupt tree, or a fetch go-git cannot do against a shallow clone) it
// falls back to cloning into a sibling temp directory and swapping it in
// with a single rename — atomic on the same filesystem, so the old tree
// stays live right up until the new one replaces it.
package gitsource

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	httpauth "github.com/go-git/go-git/v5/plumbing/transport/http"
)

// Result describes what one Sync did, so callers can log it and decide
// whether anything actually needs redeploying.
type Result struct {
	SHA     string // HEAD after the sync
	PrevSHA string // HEAD before the sync ("" if there was no checkout)
	Branch  string // branch that was checked out
	Cloned  bool   // true when a fresh clone replaced the checkout
}

// Changed reports whether the sync moved HEAD (i.e. there were new
// commits to pull).
func (r Result) Changed() bool { return r.PrevSHA != "" && r.PrevSHA != r.SHA }

// Sync brings dir up to date with repoURL at the given branch and
// returns the HEAD commit SHA. token authenticates private HTTPS repos
// (a GitHub PAT works with any username). A local filesystem path is a
// valid repoURL.
func Sync(ctx context.Context, repoURL, branch, token, dir string) (string, error) {
	res, err := SyncResult(ctx, repoURL, branch, token, dir)
	return res.SHA, err
}

// SyncResult is Sync with the full before/after detail.
func SyncResult(ctx context.Context, repoURL, branch, token, dir string) (Result, error) {
	if repoURL == "" {
		return Result{}, fmt.Errorf("empty repo URL")
	}
	auth := authFor(token)

	// Fast path: an existing checkout of the same remote — fetch + reset.
	if res, err := pull(ctx, repoURL, branch, auth, dir); err == nil {
		return res, nil
	}
	// Otherwise a fresh clone, swapped in atomically.
	return cloneSwap(ctx, repoURL, branch, auth, dir)
}

func authFor(token string) transport.AuthMethod {
	if token == "" {
		return nil
	}
	return &httpauth.BasicAuth{Username: "orxies", Password: token}
}

// errNoCheckout means dir holds no usable checkout of this remote, so a
// clone is the only option (not a failure worth reporting).
var errNoCheckout = fmt.Errorf("no usable checkout")

// pull fetches into an existing checkout and hard-resets the worktree
// onto the tracked remote branch, discarding any local drift. Returns
// errNoCheckout when dir is not a usable checkout of repoURL.
func pull(ctx context.Context, repoURL, branch string, auth transport.AuthMethod, dir string) (Result, error) {
	repo, err := git.PlainOpen(dir)
	if err != nil {
		return Result{}, errNoCheckout
	}
	remote, err := repo.Remote(git.DefaultRemoteName)
	if err != nil || !hasURL(remote.Config().URLs, repoURL) {
		return Result{}, errNoCheckout // different repo — re-clone instead
	}
	wt, err := repo.Worktree()
	if err != nil {
		return Result{}, errNoCheckout
	}

	prev := ""
	if head, herr := repo.Head(); herr == nil {
		prev = head.Hash().String()
		if branch == "" {
			branch = head.Name().Short() // whatever the clone tracked
		}
	}
	if branch == "" {
		return Result{}, errNoCheckout
	}

	spec := gitconfig.RefSpec(fmt.Sprintf("+refs/heads/%s:refs/remotes/%s/%s",
		branch, git.DefaultRemoteName, branch))
	err = repo.FetchContext(ctx, &git.FetchOptions{
		RemoteName: git.DefaultRemoteName,
		Auth:       auth,
		RefSpecs:   []gitconfig.RefSpec{spec},
		Depth:      1,
		Force:      true,
		Tags:       git.NoTags,
	})
	if err != nil && err != git.NoErrAlreadyUpToDate {
		// Shallow-fetch quirks and transport errors both land here; the
		// caller's clone fallback is the safety net.
		return Result{}, errNoCheckout
	}

	ref, err := repo.Reference(plumbing.NewRemoteReferenceName(git.DefaultRemoteName, branch), true)
	if err != nil {
		return Result{}, errNoCheckout
	}
	// Hard reset + clean: the checkout is orxies-owned, so the remote is
	// the only source of truth. Clean removes files deleted upstream.
	if err := wt.Reset(&git.ResetOptions{Mode: git.HardReset, Commit: ref.Hash()}); err != nil {
		return Result{}, errNoCheckout
	}
	if err := wt.Clean(&git.CleanOptions{Dir: true}); err != nil {
		return Result{}, errNoCheckout
	}
	return Result{SHA: ref.Hash().String(), PrevSHA: prev, Branch: branch}, nil
}

// cloneSwap clones into a sibling temp directory and renames it into
// place, so dir is only ever the old tree or the new one — never a
// half-written or missing one.
func cloneSwap(ctx context.Context, repoURL, branch string, auth transport.AuthMethod, dir string) (Result, error) {
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return Result{}, fmt.Errorf("prepare %s: %w", parent, err)
	}
	tmp, err := os.MkdirTemp(parent, "."+filepath.Base(dir)+".new-")
	if err != nil {
		return Result{}, fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(tmp) // no-op once the rename has moved it away

	opts := &git.CloneOptions{
		URL:          repoURL,
		Auth:         auth,
		Depth:        1,
		SingleBranch: true,
		Tags:         git.NoTags,
	}
	if branch != "" {
		opts.ReferenceName = plumbing.NewBranchReferenceName(branch)
	}
	repo, err := git.PlainCloneContext(ctx, tmp, false, opts)
	if err != nil {
		return Result{}, fmt.Errorf("clone: %w", err)
	}
	head, err := repo.Head()
	if err != nil {
		return Result{}, err
	}

	prev := ""
	if old, oerr := git.PlainOpen(dir); oerr == nil {
		if h, herr := old.Head(); herr == nil {
			prev = h.Hash().String()
		}
	}
	if err := swapDir(tmp, dir); err != nil {
		return Result{}, err
	}
	return Result{
		SHA:     head.Hash().String(),
		PrevSHA: prev,
		Branch:  head.Name().Short(),
		Cloned:  true,
	}, nil
}

// swapDir moves fresh onto dst, keeping dst readable throughout: the old
// tree is renamed aside first and only deleted once the new one is in
// place (and restored if the second rename fails).
func swapDir(fresh, dst string) error {
	retired := ""
	if _, err := os.Stat(dst); err == nil {
		retired = dst + ".old-" + randSuffix()
		if err := os.Rename(dst, retired); err != nil {
			return fmt.Errorf("retire %s: %w", dst, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(fresh, dst); err != nil {
		if retired != "" {
			_ = os.Rename(retired, dst) // put the live tree back
		}
		return fmt.Errorf("install %s: %w", dst, err)
	}
	if retired != "" {
		_ = os.RemoveAll(retired)
	}
	return nil
}

func randSuffix() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "tmp"
	}
	return hex.EncodeToString(b)
}

// hasURL reports whether a remote is configured for want, tolerating a
// trailing ".git" or slash on either side.
func hasURL(urls []string, want string) bool {
	norm := func(s string) string {
		s = strings.TrimSuffix(strings.TrimSpace(s), "/")
		return strings.TrimSuffix(s, ".git")
	}
	want = norm(want)
	for _, u := range urls {
		if norm(u) == want {
			return true
		}
	}
	return false
}
