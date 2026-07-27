package ui

import (
	"fmt"
	"net/http"
)

// sysView is the formatted host-health snapshot the System page renders.
type sysView struct {
	Available   bool
	CPUPercent  int
	CPUCount    int
	MemPercent  int
	MemUsed     string
	MemTotal    string
	SwapPercent int
	SwapUsed    string
	SwapTotal   string
	HasSwap     bool
	DiskPercent int
	DiskUsed    string
	DiskTotal   string
	Load1       string
	Load5       string
	Load15      string
	Uptime      string
}

func (s *Server) sysView() sysView {
	st := s.Sys.Read()
	v := sysView{Available: st.Available, CPUCount: st.CPUCount}
	if !st.Available {
		return v
	}
	v.CPUPercent = round(st.CPUPercent)
	v.MemUsed, v.MemTotal = humanBytes(st.MemUsed), humanBytes(st.MemTotal)
	v.MemPercent = pctOf(st.MemUsed, st.MemTotal)
	v.SwapUsed, v.SwapTotal = humanBytes(st.SwapUsed), humanBytes(st.SwapTotal)
	v.SwapPercent = pctOf(st.SwapUsed, st.SwapTotal)
	v.HasSwap = st.SwapTotal > 0
	v.DiskUsed, v.DiskTotal = humanBytes(st.DiskUsed), humanBytes(st.DiskTotal)
	v.DiskPercent = pctOf(st.DiskUsed, st.DiskTotal)
	v.Load1 = fmt.Sprintf("%.2f", st.Load1)
	v.Load5 = fmt.Sprintf("%.2f", st.Load5)
	v.Load15 = fmt.Sprintf("%.2f", st.Load15)
	v.Uptime = humanUptime(st.UptimeSecs)
	return v
}

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/system" {
		http.NotFound(w, r)
		return
	}
	type data struct {
		baseData
		Sys sysView
	}
	s.render(w, "layout", data{
		baseData: s.page(w, r, "System", "system", "system"),
		Sys:      s.sysView(),
	})
}

func (s *Server) handleSystemPartial(w http.ResponseWriter, r *http.Request) {
	s.render(w, "system-meters", s.sysView())
}

func pctOf(used, total uint64) int {
	if total == 0 {
		return 0
	}
	return round(float64(used) / float64(total) * 100)
}

func round(f float64) int { return int(f + 0.5) }

func humanUptime(secs uint64) string {
	d := secs / 86400
	h := (secs % 86400) / 3600
	m := (secs % 3600) / 60
	switch {
	case d > 0:
		return fmt.Sprintf("%dd %dh %dm", d, h, m)
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	default:
		return fmt.Sprintf("%dm", m)
	}
}
