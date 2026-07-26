package store

import (
	"database/sql"
	"errors"
)

// Default loopback port range for app containers (documented in
// docs/PHASE-3.md §6). Not user-facing — the edge proxies to these.
const (
	PortRangeLo = 8300
	PortRangeHi = 8999
)

// ErrNoFreePort means the app-container port range is exhausted.
var ErrNoFreePort = errors.New("no free port in range")

// AllocatePort reserves and returns the lowest free host port in
// [lo,hi] not already reserved, binding it to deploymentID. Reservation
// is atomic within the process (the DB uses a single writer conn).
func (s *Store) AllocatePort(deploymentID int64, lo, hi int) (int, error) {
	for p := lo; p <= hi; p++ {
		var existing int
		err := s.db.QueryRow(`SELECT host_port FROM port_allocations WHERE host_port=?`, p).Scan(&existing)
		if errors.Is(err, sql.ErrNoRows) {
			if _, err := s.db.Exec(
				`INSERT INTO port_allocations (host_port, deployment_id) VALUES (?,?)`, p, deploymentID); err != nil {
				return 0, err
			}
			return p, nil
		}
		if err != nil {
			return 0, err
		}
	}
	return 0, ErrNoFreePort
}

// ReleasePort frees a previously allocated port.
func (s *Store) ReleasePort(port int) error {
	_, err := s.db.Exec(`DELETE FROM port_allocations WHERE host_port=?`, port)
	return err
}
