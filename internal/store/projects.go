package store

import (
	"database/sql"
	"errors"
	"time"
)

// scanner is satisfied by *sql.Row and *sql.Rows.
type scanner interface{ Scan(...any) error }

// Project is a deployable unit: a source (local path in Phase 3, a Git
// repo later), a build strategy, and the domain it serves.
type Project struct {
	ID         int64
	Name       string
	SourcePath string // local path source (Phase 3) or the repo checkout dir
	Strategy   string // "nixpacks" | "dockerfile" | "static"
	BuildCmd   string
	RunCmd     string
	AppPort    int
	Domain     string
	CreatedAt  time.Time
	// Phase 4: git source.
	RepoURL       string // if set, the project is deployed from this Git repo
	Branch        string // branch to track ("" = default)
	TokenEnc      string // AES-GCM-encrypted access token for private repos
	WebhookSecret string // HMAC secret for deploy-on-push webhooks
	EnvEnc        string // AES-GCM-encrypted JSON of custom env vars
}

const projectCols = `id, name, source_path, strategy, build_cmd, run_cmd, app_port, domain, created_at, repo_url, branch, token_enc, webhook_secret, env_enc`

func scanProject(row scanner) (*Project, error) {
	var p Project
	var created string
	err := row.Scan(&p.ID, &p.Name, &p.SourcePath, &p.Strategy, &p.BuildCmd, &p.RunCmd,
		&p.AppPort, &p.Domain, &created, &p.RepoURL, &p.Branch, &p.TokenEnc, &p.WebhookSecret, &p.EnvEnc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.CreatedAt = parseTime(created)
	return &p, nil
}

// CreateProject inserts p and sets p.ID.
func (s *Store) CreateProject(p *Project) error {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	res, err := s.db.Exec(
		`INSERT INTO projects (name, source_path, strategy, build_cmd, run_cmd, app_port, domain, created_at, repo_url, branch, token_enc, webhook_secret, env_enc)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.Name, p.SourcePath, p.Strategy, p.BuildCmd, p.RunCmd, p.AppPort, p.Domain,
		p.CreatedAt.Format(tsLayout), p.RepoURL, p.Branch, p.TokenEnc, p.WebhookSecret, p.EnvEnc)
	if err != nil {
		return err
	}
	p.ID, _ = res.LastInsertId()
	return nil
}

// GetProject returns the project by id, or ErrNotFound.
func (s *Store) GetProject(id int64) (*Project, error) {
	return scanProject(s.db.QueryRow(`SELECT `+projectCols+` FROM projects WHERE id=?`, id))
}

// ProjectByName returns the project by unique name, or ErrNotFound.
func (s *Store) ProjectByName(name string) (*Project, error) {
	return scanProject(s.db.QueryRow(`SELECT `+projectCols+` FROM projects WHERE name=?`, name))
}

// ListProjects returns all projects, newest first.
func (s *Store) ListProjects() ([]*Project, error) {
	rows, err := s.db.Query(`SELECT ` + projectCols + ` FROM projects ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdateProject saves mutable fields of p.
func (s *Store) UpdateProject(p *Project) error {
	_, err := s.db.Exec(
		`UPDATE projects SET source_path=?, strategy=?, build_cmd=?, run_cmd=?, app_port=?, domain=?,
		 repo_url=?, branch=?, token_enc=?, webhook_secret=?, env_enc=? WHERE id=?`,
		p.SourcePath, p.Strategy, p.BuildCmd, p.RunCmd, p.AppPort, p.Domain,
		p.RepoURL, p.Branch, p.TokenEnc, p.WebhookSecret, p.EnvEnc, p.ID)
	return err
}

// DeleteProject removes a project and (via cascade) its deployments.
func (s *Store) DeleteProject(id int64) error {
	_, err := s.db.Exec(`DELETE FROM projects WHERE id=?`, id)
	return err
}
