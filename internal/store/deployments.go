package store

import (
	"database/sql"
	"errors"
	"time"
)

// Deployment statuses.
const (
	StatusQueued   = "queued"
	StatusBuilding = "building"
	StatusRunning  = "running"
	StatusFailed   = "failed"
	StatusStopped  = "stopped"
)

// Deployment is one build+run attempt of a Project.
type Deployment struct {
	ID          int64
	ProjectID   int64
	Status      string
	ImageRef    string
	ContainerID string
	HostPort    int
	CommitSHA   string
	CreatedAt   time.Time
	FinishedAt  *time.Time
}

const deploymentCols = `id, project_id, status, image_ref, container_id, host_port, commit_sha, created_at, finished_at`

func scanDeployment(row scanner) (*Deployment, error) {
	var d Deployment
	var created string
	var finished sql.NullString
	err := row.Scan(&d.ID, &d.ProjectID, &d.Status, &d.ImageRef, &d.ContainerID,
		&d.HostPort, &d.CommitSHA, &created, &finished)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d.CreatedAt = parseTime(created)
	if finished.Valid && finished.String != "" {
		t := parseTime(finished.String)
		d.FinishedAt = &t
	}
	return &d, nil
}

// CreateDeployment inserts d (status defaults to queued) and sets d.ID.
func (s *Store) CreateDeployment(d *Deployment) error {
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now().UTC()
	}
	if d.Status == "" {
		d.Status = StatusQueued
	}
	res, err := s.db.Exec(
		`INSERT INTO deployments (project_id, status, image_ref, container_id, host_port, commit_sha, created_at)
		 VALUES (?,?,?,?,?,?,?)`,
		d.ProjectID, d.Status, d.ImageRef, d.ContainerID, d.HostPort, d.CommitSHA, d.CreatedAt.Format(tsLayout))
	if err != nil {
		return err
	}
	d.ID, _ = res.LastInsertId()
	return nil
}

// UpdateDeployment saves mutable fields. If status is terminal
// (failed/stopped/running) callers may set FinishedAt.
func (s *Store) UpdateDeployment(d *Deployment) error {
	var finished any
	if d.FinishedAt != nil {
		finished = d.FinishedAt.Format(tsLayout)
	}
	_, err := s.db.Exec(
		`UPDATE deployments SET status=?, image_ref=?, container_id=?, host_port=?, commit_sha=?, finished_at=? WHERE id=?`,
		d.Status, d.ImageRef, d.ContainerID, d.HostPort, d.CommitSHA, finished, d.ID)
	return err
}

// GetDeployment returns a deployment by id, or ErrNotFound.
func (s *Store) GetDeployment(id int64) (*Deployment, error) {
	return scanDeployment(s.db.QueryRow(`SELECT `+deploymentCols+` FROM deployments WHERE id=?`, id))
}

// LatestDeployment returns the most recent deployment for a project, or
// ErrNotFound if the project has none yet.
func (s *Store) LatestDeployment(projectID int64) (*Deployment, error) {
	return scanDeployment(s.db.QueryRow(
		`SELECT `+deploymentCols+` FROM deployments WHERE project_id=? ORDER BY id DESC LIMIT 1`, projectID))
}

// ListDeployments returns a project's deployments, newest first.
func (s *Store) ListDeployments(projectID int64) ([]*Deployment, error) {
	rows, err := s.db.Query(`SELECT `+deploymentCols+` FROM deployments WHERE project_id=? ORDER BY id DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Deployment
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
