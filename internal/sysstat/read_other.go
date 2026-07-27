//go:build !linux

package sysstat

import "runtime"

// Read reports Unavailable on non-Linux (dev machines). Host metrics
// come from /proc, which only exists on Linux — where orxies runs in prod.
func (r *Reader) Read() Stats {
	return Stats{Available: false, CPUCount: runtime.NumCPU()}
}

// ListeningPorts is empty off Linux.
func ListeningPorts() []int { return nil }
