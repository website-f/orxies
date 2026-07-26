package store

import (
	"database/sql"
	"errors"
	"time"
)

// Service is a managed datastore (a DB/cache container orxies runs) or a
// pointer to an external one. Credentials are stored encrypted (CredsEnc
// holds AES-GCM JSON).
type Service struct {
	ID          int64
	Name        string
	Engine      string // "postgres" | "mysql" | "redis"
	Mode        string // "managed" | "external"
	ContainerID string
	Status      string // running | stopped | external
	CredsEnc    string
	CreatedAt   time.Time
}

const serviceCols = `id, name, engine, mode, container_id, status, creds_enc, created_at`

func scanService(row scanner) (*Service, error) {
	var s Service
	var created string
	err := row.Scan(&s.ID, &s.Name, &s.Engine, &s.Mode, &s.ContainerID, &s.Status, &s.CredsEnc, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.CreatedAt = parseTime(created)
	return &s, nil
}

// CreateService inserts svc and sets svc.ID.
func (s *Store) CreateService(svc *Service) error {
	if svc.CreatedAt.IsZero() {
		svc.CreatedAt = time.Now().UTC()
	}
	res, err := s.db.Exec(
		`INSERT INTO services (name, engine, mode, container_id, status, creds_enc, created_at) VALUES (?,?,?,?,?,?,?)`,
		svc.Name, svc.Engine, svc.Mode, svc.ContainerID, svc.Status, svc.CredsEnc, svc.CreatedAt.Format(tsLayout))
	if err != nil {
		return err
	}
	svc.ID, _ = res.LastInsertId()
	return nil
}

// GetService returns a service by id, or ErrNotFound.
func (s *Store) GetService(id int64) (*Service, error) {
	return scanService(s.db.QueryRow(`SELECT `+serviceCols+` FROM services WHERE id=?`, id))
}

// ListServices returns all services, newest first.
func (s *Store) ListServices() ([]*Service, error) {
	rows, err := s.db.Query(`SELECT ` + serviceCols + ` FROM services ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectServices(rows)
}

// UpdateService saves mutable fields.
func (s *Store) UpdateService(svc *Service) error {
	_, err := s.db.Exec(`UPDATE services SET container_id=?, status=?, creds_enc=? WHERE id=?`,
		svc.ContainerID, svc.Status, svc.CredsEnc, svc.ID)
	return err
}

// DeleteService removes a service (and its project links, via cascade).
func (s *Store) DeleteService(id int64) error {
	_, err := s.db.Exec(`DELETE FROM services WHERE id=?`, id)
	return err
}

// ---- project ↔ service links ----

// LinkService links a service to a project (idempotent).
func (s *Store) LinkService(projectID, serviceID int64) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO project_services (project_id, service_id) VALUES (?,?)`, projectID, serviceID)
	return err
}

// UnlinkService removes a link.
func (s *Store) UnlinkService(projectID, serviceID int64) error {
	_, err := s.db.Exec(`DELETE FROM project_services WHERE project_id=? AND service_id=?`, projectID, serviceID)
	return err
}

// SetProjectServices replaces a project's linked-service set.
func (s *Store) SetProjectServices(projectID int64, serviceIDs []int64) error {
	if _, err := s.db.Exec(`DELETE FROM project_services WHERE project_id=?`, projectID); err != nil {
		return err
	}
	for _, sid := range serviceIDs {
		if err := s.LinkService(projectID, sid); err != nil {
			return err
		}
	}
	return nil
}

// LinkedServices returns the services linked to a project.
func (s *Store) LinkedServices(projectID int64) ([]*Service, error) {
	rows, err := s.db.Query(
		`SELECT s.id, s.name, s.engine, s.mode, s.container_id, s.status, s.creds_enc, s.created_at
		 FROM services s JOIN project_services ps ON ps.service_id = s.id
		 WHERE ps.project_id = ? ORDER BY s.id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectServices(rows)
}

func collectServices(rows *sql.Rows) ([]*Service, error) {
	var out []*Service
	for rows.Next() {
		svc, err := scanService(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, svc)
	}
	return out, rows.Err()
}
