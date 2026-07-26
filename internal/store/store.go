// Package store is orxies's platform state: projects, deployments, and
// port allocations, persisted in a single embedded SQLite file.
//
// It uses the pure-Go modernc.org/sqlite driver so the static
// CGO_ENABLED=0 build is preserved — no cgo, no libc dependency.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row lookup misses.
var ErrNotFound = errors.New("not found")

// Store wraps the SQLite database handle.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the database at path and applies
// migrations. WAL + a busy timeout keep concurrent reads/writes sane.
func Open(path string) (*Store, error) {
	dsn := "file:" + path +
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: serialize writers; simplest correct default
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open db: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// migrations are applied in order; the applied count is tracked in the
// SQLite user_version pragma. Each entry is one statement.
var migrations = []string{
	`CREATE TABLE projects (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		name        TEXT NOT NULL UNIQUE,
		source_path TEXT NOT NULL,
		strategy    TEXT NOT NULL,
		build_cmd   TEXT NOT NULL DEFAULT '',
		run_cmd     TEXT NOT NULL DEFAULT '',
		app_port    INTEGER NOT NULL DEFAULT 0,
		domain      TEXT NOT NULL DEFAULT '',
		created_at  TEXT NOT NULL
	)`,
	`CREATE TABLE deployments (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		status       TEXT NOT NULL,
		image_ref    TEXT NOT NULL DEFAULT '',
		container_id TEXT NOT NULL DEFAULT '',
		host_port    INTEGER NOT NULL DEFAULT 0,
		commit_sha   TEXT NOT NULL DEFAULT '',
		created_at   TEXT NOT NULL,
		finished_at  TEXT
	)`,
	`CREATE TABLE port_allocations (
		host_port     INTEGER PRIMARY KEY,
		deployment_id INTEGER REFERENCES deployments(id) ON DELETE SET NULL
	)`,
	`CREATE INDEX idx_deployments_project ON deployments(project_id)`,
	// Phase 4: git-backed projects.
	`ALTER TABLE projects ADD COLUMN repo_url TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE projects ADD COLUMN branch TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE projects ADD COLUMN token_enc TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE projects ADD COLUMN webhook_secret TEXT NOT NULL DEFAULT ''`,
	// Phase 5: managed services + per-project env.
	`ALTER TABLE projects ADD COLUMN env_enc TEXT NOT NULL DEFAULT ''`,
	`CREATE TABLE services (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		name         TEXT NOT NULL UNIQUE,
		engine       TEXT NOT NULL,               -- postgres | mysql | redis
		mode         TEXT NOT NULL,               -- managed | external
		container_id TEXT NOT NULL DEFAULT '',
		status       TEXT NOT NULL DEFAULT '',
		creds_enc    TEXT NOT NULL DEFAULT '',     -- encrypted JSON credentials
		created_at   TEXT NOT NULL
	)`,
	`CREATE TABLE project_services (
		project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
		PRIMARY KEY (project_id, service_id)
	)`,
}

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	for i := version; i < len(migrations); i++ {
		if _, err := s.db.Exec(migrations[i]); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		// user_version can't be parameterized; i+1 is an int we control.
		if _, err := s.db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			return err
		}
	}
	return nil
}

const tsLayout = time.RFC3339

func parseTime(s string) time.Time {
	t, _ := time.Parse(tsLayout, s)
	return t
}
