//go:build linux

package sysstat

import (
	"os"
	"runtime"
	"syscall"
)

// Read collects a fresh host snapshot from /proc + statfs.
func (r *Reader) Read() Stats {
	s := Stats{Available: true, CPUCount: runtime.NumCPU()}

	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		total, avail, swT, swF := parseMeminfo(string(b))
		s.MemTotal, s.MemAvailable = total, avail
		if total > avail {
			s.MemUsed = total - avail
		}
		s.SwapTotal = swT
		if swT > swF {
			s.SwapUsed = swT - swF
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		s.Load1, s.Load5, s.Load15 = parseLoadAvg(string(b))
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		s.UptimeSecs = parseUptime(string(b))
	}
	if b, err := os.ReadFile("/proc/stat"); err == nil {
		idle, total := parseCPUStat(string(b))
		s.CPUPercent = r.cpuPercent(idle, total)
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(r.diskPath, &st); err == nil {
		bs := uint64(st.Bsize)
		s.DiskTotal = st.Blocks * bs
		s.DiskUsed = (st.Blocks - st.Bavail) * bs
	}
	return s
}

// ListeningPorts returns the host's TCP LISTEN ports (IPv4 + IPv6).
// Under host networking these are the ports actually taken on the box.
func ListeningPorts() []int {
	set := map[int]bool{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if b, err := os.ReadFile(path); err == nil {
			for _, p := range parseProcNetTCP(string(b)) {
				set[p] = true
			}
		}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	return out
}
