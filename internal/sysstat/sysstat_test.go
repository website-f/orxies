package sysstat

import "testing"

func TestParseMeminfo(t *testing.T) {
	data := `MemTotal:       16384000 kB
MemFree:         1000000 kB
MemAvailable:    8192000 kB
SwapTotal:       2048000 kB
SwapFree:        2048000 kB
`
	total, avail, swT, swF := parseMeminfo(data)
	if total != 16384000*1024 || avail != 8192000*1024 {
		t.Errorf("mem total/avail = %d/%d", total, avail)
	}
	if swT != 2048000*1024 || swF != 2048000*1024 {
		t.Errorf("swap = %d/%d", swT, swF)
	}
}

func TestParseLoadAvg(t *testing.T) {
	l1, l5, l15 := parseLoadAvg("0.52 0.48 0.40 2/812 12345")
	if l1 != 0.52 || l5 != 0.48 || l15 != 0.40 {
		t.Errorf("load = %v %v %v", l1, l5, l15)
	}
}

func TestParseUptime(t *testing.T) {
	if got := parseUptime("123456.78 90000.00"); got != 123456 {
		t.Errorf("uptime = %d, want 123456", got)
	}
}

func TestParseCPUStat(t *testing.T) {
	// cpu  user nice system idle iowait irq softirq steal
	idle, total := parseCPUStat("cpu  100 0 50 800 0 0 0 0\ncpu0 100 0 50 800 0 0 0 0\n")
	if idle != 800 || total != 950 {
		t.Fatalf("idle/total = %d/%d, want 800/950", idle, total)
	}
}

func TestCPUPercentDelta(t *testing.T) {
	r := &Reader{prevIdle: 800, prevTotal: 1000}
	// next: total +200, idle +100 → 50% busy
	if pct := r.cpuPercent(900, 1200); pct < 49.9 || pct > 50.1 {
		t.Errorf("cpuPercent = %.2f, want ~50", pct)
	}
}

func TestParseProcNetTCP(t *testing.T) {
	// header + one LISTEN on port 0x1F90 (8080) + one non-listen (state 01)
	data := `  sl  local_address rem_address   st ...
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 0
   1: 0100007F:C000 0A0A0A0A:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 0
   2: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0
`
	ports := parseProcNetTCP(data)
	has := func(p int) bool {
		for _, x := range ports {
			if x == p {
				return true
			}
		}
		return false
	}
	if !has(8080) {
		t.Errorf("expected 8080 (0x1F90) LISTEN, got %v", ports)
	}
	if !has(80) {
		t.Errorf("expected 80 (0x0050) LISTEN, got %v", ports)
	}
	if has(0xC000) {
		t.Errorf("non-LISTEN socket leaked into ports: %v", ports)
	}
}
