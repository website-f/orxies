package ui

import (
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"orxies/internal/sysstat"
)

// portUse is one occupied loopback port and what holds it.
type portUse struct {
	Port int
	By   string
}

// portInfo returns the loopback ports currently in use (from configured
// site upstreams, running project deployments, and actual host LISTEN
// sockets) plus a suggested free port for a new manual upstream.
func (s *Server) portInfo() (used []portUse, suggestedUpstream string) {
	byPort := map[int]string{}

	// Configured site upstreams that target loopback.
	for _, site := range s.Store.Snapshot() {
		for _, up := range site.Upstreams {
			if p, ok := loopbackPort(up); ok {
				if _, seen := byPort[p]; !seen {
					byPort[p] = "site: " + site.Domain
				}
			}
		}
	}
	// Running project deployments (auto-allocated ports).
	if s.DB != nil {
		if projs, err := s.DB.ListProjects(); err == nil {
			for _, pr := range projs {
				if d, err := s.DB.LatestDeployment(pr.ID); err == nil && d.HostPort > 0 {
					byPort[d.HostPort] = "project: " + pr.Name
				}
			}
		}
	}
	// Actual host listeners (authoritative; only populated on Linux).
	for _, p := range sysstat.ListeningPorts() {
		if _, seen := byPort[p]; !seen {
			byPort[p] = "in use"
		}
	}

	for p, by := range byPort {
		used = append(used, portUse{Port: p, By: by})
	}
	sort.Slice(used, func(i, j int) bool { return used[i].Port < used[j].Port })

	// Suggest the lowest free port in the manual range (8000-8299),
	// leaving 8300-8999 for orxies' own project auto-allocation.
	for p := 8000; p <= 8299; p++ {
		if _, taken := byPort[p]; !taken {
			suggestedUpstream = "127.0.0.1:" + strconv.Itoa(p)
			break
		}
	}
	return used, suggestedUpstream
}

// loopbackPort extracts the port from an upstream that targets the local
// host (127.0.0.1 / localhost / ::1). Returns ok=false for external hosts.
func loopbackPort(upstream string) (int, bool) {
	u := strings.TrimSpace(upstream)
	if strings.Contains(u, "://") {
		if pu, err := url.Parse(u); err == nil {
			u = pu.Host
		}
	}
	host, portStr, err := net.SplitHostPort(u)
	if err != nil {
		return 0, false
	}
	switch host {
	case "127.0.0.1", "localhost", "::1":
	default:
		return 0, false
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, false
	}
	return p, true
}
