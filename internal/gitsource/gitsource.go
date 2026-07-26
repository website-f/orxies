// Package gitsource clones a project's Git repository so the deploy
// engine can build from a working tree. It uses go-git (pure Go — no
// external `git` binary, keeps the CGO-free build).
//
// Phase 4 keeps it simple and bulletproof: every sync is a fresh shallow
// clone. Incremental fetch is a later optimization.
package gitsource

import (
	"context"
	"fmt"
	"os"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	httpauth "github.com/go-git/go-git/v5/plumbing/transport/http"
)

// Sync (re)clones repoURL into dir at the given branch and returns the
// HEAD commit SHA. token authenticates private HTTPS repos (a GitHub PAT
// works with any username). A local filesystem path is a valid repoURL.
func Sync(ctx context.Context, repoURL, branch, token, dir string) (string, error) {
	if repoURL == "" {
		return "", fmt.Errorf("empty repo URL")
	}
	if err := os.RemoveAll(dir); err != nil {
		return "", fmt.Errorf("clean %s: %w", dir, err)
	}
	var auth transport.AuthMethod
	if token != "" {
		auth = &httpauth.BasicAuth{Username: "orxies", Password: token}
	}
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
	repo, err := git.PlainCloneContext(ctx, dir, false, opts)
	if err != nil {
		return "", fmt.Errorf("clone: %w", err)
	}
	head, err := repo.Head()
	if err != nil {
		return "", err
	}
	return head.Hash().String(), nil
}
