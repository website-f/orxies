// Package sysstat exposes lightweight host health metrics (CPU, RAM,
// swap, disk, load, uptime) and the set of listening TCP ports. On Linux
// it reads /proc + statfs; elsewhere it reports Unavailable (so dev
// builds on macOS/Windows still compile — see read_linux.go / read_other.go).
//
// The parsing functions here are pure (string in, numbers out) so they
// are unit-tested on any OS.
package sysstat

import (
	"strconv"
	"strings"
)

// Stats is a snapshot of host health. Sizes are bytes.
type Stats struct {
	Available    bool
	Load1        float64
	Load5        float64
	Load15       float64
	CPUCount     int
	CPUPercent   float64 // 0..100, averaged over the interval since the last Read
	MemTotal     uint64
	MemAvailable uint64
	MemUsed      uint64
	SwapTotal    uint64
	SwapUsed     uint64
	DiskTotal    uint64
	DiskUsed     uint64
	UptimeSecs   uint64
}

// Reader holds the state needed to compute CPU% deltas across reads.
// Create one and reuse it (safe for sequential polling).
type Reader struct {
	diskPath  string
	prevIdle  uint64
	prevTotal uint64
}

// New returns a Reader that measures disk usage on the filesystem
// containing diskPath (e.g. the data dir).
func New(diskPath string) *Reader { return &Reader{diskPath: diskPath} }

// ---- pure parsers (testable everywhere) ----

// parseMeminfo returns total, available, swapTotal, swapFree in bytes.
func parseMeminfo(data string) (total, available, swapTotal, swapFree uint64) {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kb, _ := strconv.ParseUint(fields[1], 10, 64)
		bytes := kb * 1024
		switch fields[0] {
		case "MemTotal:":
			total = bytes
		case "MemAvailable:":
			available = bytes
		case "SwapTotal:":
			swapTotal = bytes
		case "SwapFree:":
			swapFree = bytes
		}
	}
	return
}

// parseLoadAvg returns the 1/5/15-minute load averages.
func parseLoadAvg(data string) (l1, l5, l15 float64) {
	f := strings.Fields(data)
	if len(f) >= 3 {
		l1, _ = strconv.ParseFloat(f[0], 64)
		l5, _ = strconv.ParseFloat(f[1], 64)
		l15, _ = strconv.ParseFloat(f[2], 64)
	}
	return
}

// parseUptime returns whole seconds of uptime.
func parseUptime(data string) uint64 {
	f := strings.Fields(data)
	if len(f) == 0 {
		return 0
	}
	secs, _ := strconv.ParseFloat(f[0], 64)
	return uint64(secs)
}

// parseCPUStat returns (idle, total) jiffies from the aggregate "cpu"
// line of /proc/stat.
func parseCPUStat(data string) (idle, total uint64) {
	for _, line := range strings.Split(data, "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:] // user nice system idle iowait irq softirq steal ...
		for i, f := range fields {
			v, _ := strconv.ParseUint(f, 10, 64)
			total += v
			if i == 3 || i == 4 { // idle + iowait
				idle += v
			}
		}
		return
	}
	return
}

// cpuPercent computes utilisation from the previous snapshot and updates
// it. The first call (prev == 0) yields the average since boot; each
// subsequent call yields the average over the interval since the last.
func (r *Reader) cpuPercent(idle, total uint64) float64 {
	dt := total - r.prevTotal
	di := idle - r.prevIdle
	r.prevTotal, r.prevIdle = total, idle
	if dt == 0 {
		return 0
	}
	pct := (1 - float64(di)/float64(dt)) * 100
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct
}

// parseProcNetTCP extracts the local ports of sockets in LISTEN state
// (state 0A) from a /proc/net/tcp or tcp6 dump.
func parseProcNetTCP(data string) []int {
	var ports []int
	seen := map[int]bool{}
	lines := strings.Split(data, "\n")
	for i, line := range lines {
		if i == 0 { // header
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		if f[3] != "0A" { // 0A = TCP_LISTEN
			continue
		}
		local := f[1] // "0100007F:1F90"
		c := strings.LastIndexByte(local, ':')
		if c < 0 {
			continue
		}
		p, err := strconv.ParseInt(local[c+1:], 16, 32)
		if err != nil {
			continue
		}
		if !seen[int(p)] {
			seen[int(p)] = true
			ports = append(ports, int(p))
		}
	}
	return ports
}
