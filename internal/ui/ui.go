// Package ui is the admin web interface for orxies.
package ui

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"orxies/internal/acme"
	"orxies/internal/audit"
	"orxies/internal/auth"
	"orxies/internal/config"
	"orxies/internal/deploy"
	"orxies/internal/metrics"
	"orxies/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Server bundles all UI dependencies and the template set. Wire it
// once at startup and call Handler() to obtain an http.Handler.
type Server struct {
	Store         *config.Store
	Metrics       *metrics.Registry
	Auth          *auth.Manager
	ACME          *acme.Manager
	SitesDir      string
	Version       string
	StartAt       time.Time
	Audit         *audit.Logger   // admin-action log (nil-safe)
	LoginThrottle *auth.Throttle  // brute-force protection for /login
	DB            *store.Store    // platform state (projects/deployments); nil disables Projects
	Deploy        *deploy.Manager // deployment orchestrator; nil disables Projects
	// ReloadCallback is invoked after the UI mutates a site file —
	// used to re-trigger the watcher's reload synchronously so the
	// UI shows the change immediately. Optional.
	ReloadCallback func(ctx context.Context)

	tpl    *template.Template
	static http.Handler

	// In-memory capture of the most recent deploy per project (build
	// output streams here; the detail page polls it).
	projMu        sync.Mutex
	projLogs      map[int64]*logBuf
	projDeploying map[int64]bool
	svcLogs       map[int64]*logBuf
	svcBusy       map[int64]bool
}

// New parses templates and returns a ready Server.
func New(s *Server) (*Server, error) {
	if s.LoginThrottle == nil {
		s.LoginThrottle = auth.NewThrottle()
	}
	s.projLogs = map[int64]*logBuf{}
	s.projDeploying = map[int64]bool{}
	s.svcLogs = map[int64]*logBuf{}
	s.svcBusy = map[int64]bool{}
	funcs := template.FuncMap{
		"join": func(items []string, sep string) string { return strings.Join(items, sep) },
		"icon": func(name string) template.HTML {
			return template.HTML(`<svg class="icon" aria-hidden="true"><use href="/static/icons.svg#i-` +
				template.HTMLEscapeString(name) + `"/></svg>`)
		},
		"spark":      func(series []uint32) template.HTML { return renderSpark(series, 108, 26, "spark") },
		"sparkLarge": func(series []uint32) template.HTML { return renderSpark(series, 600, 60, "spark spark-lg") },
	}
	tpl, err := template.New("").Funcs(funcs).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s.tpl = tpl

	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	s.static = http.StripPrefix("/static/", http.FileServer(http.FS(staticFS)))

	return s, nil
}

// Handler returns the routing mux for the admin UI.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/static/", s.serveStatic)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)

	// Authenticated routes.
	authed := http.NewServeMux()
	authed.HandleFunc("/", s.handleDashboard)
	authed.HandleFunc("/sites", s.handleSitesList)
	authed.HandleFunc("/sites/new", s.handleSiteNew)
	authed.HandleFunc("/sites/", s.handleSitesItem) // /sites/<file>, /sites/<file>/toggle, /sites/<file>/delete
	authed.HandleFunc("/certs", s.handleCerts)
	authed.HandleFunc("/partials/site-rows", s.handleSiteRowsPartial)
	if s.DB != nil && s.Deploy != nil {
		authed.HandleFunc("/projects", s.handleProjects)
		authed.HandleFunc("/projects/new", s.handleProjectNew)
		authed.HandleFunc("/projects/", s.handleProjectItem) // /projects/<id>[/deploy|/stop|/remove|/logs|/services|/env]
		authed.HandleFunc("/services", s.handleServices)
		authed.HandleFunc("/services/new", s.handleServiceNew)
		authed.HandleFunc("/services/", s.handleServiceItem) // /services/<id>[/provision|/remove|/logs]
	}

	mux.Handle("/", s.Auth.Require(authed))
	return mux
}

// projectsEnabled reports whether the platform (store + agent) is wired.
func (s *Server) projectsEnabled() bool { return s.DB != nil && s.Deploy != nil }

// ---- Helpers ----

type baseData struct {
	Title           string
	Active          string
	Version         string
	SiteCount       int
	Uptime          string
	CSRF            string // token for forms on this page
	ProjectsEnabled bool   // whether the Projects section is enabled
	ContentTemplate string // name of the body template the layout should render
}

func (s *Server) base(title, active, contentTpl string) baseData {
	return baseData{
		Title:           title,
		Active:          active,
		Version:         s.Version,
		SiteCount:       len(s.Store.Snapshot()),
		Uptime:          humanDuration(time.Since(s.StartAt)),
		ProjectsEnabled: s.projectsEnabled(),
		ContentTemplate: contentTpl,
	}
}

// page is base() plus a freshly-ensured CSRF token. Use for any
// authenticated page that renders a form.
func (s *Server) page(w http.ResponseWriter, r *http.Request, title, active, contentTpl string) baseData {
	b := s.base(title, active, contentTpl)
	b.CSRF = s.Auth.EnsureCSRF(w, r)
	return b
}

// user returns the authenticated admin username for audit records.
func (s *Server) user(r *http.Request) string { return s.Auth.Authenticated(r) }

// audit writes one admin-action record (nil-safe).
func (s *Server) audit(r *http.Request, user, action, target, result string) {
	s.Audit.Log(r, user, action, target, result)
}

// serveStatic serves embedded assets but refuses directory listings.
func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/") {
		http.NotFound(w, r)
		return
	}
	s.static.ServeHTTP(w, r)
}

// clientPeerIP returns the direct peer IP (never a forwarded header) —
// used for login throttling so a spoofed header can't dodge the lockout.
func clientPeerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// safeNext sanitises a post-login redirect target to a local path,
// rejecting protocol-relative ("//host") and backslash ("/\\host")
// forms that browsers resolve as absolute URLs (open-redirect).
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") {
		return "/"
	}
	if strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	return next
}

func humanDuration(d time.Duration) string {
	d = d.Truncate(time.Second)
	if d < time.Minute {
		return d.String()
	}
	if d < time.Hour {
		return strconv.Itoa(int(d.Minutes())) + "m"
	}
	if d < 24*time.Hour {
		return strconv.Itoa(int(d.Hours())) + "h " + strconv.Itoa(int(d.Minutes())%60) + "m"
	}
	days := int(d.Hours()) / 24
	return strconv.Itoa(days) + "d " + strconv.Itoa(int(d.Hours())%24) + "h"
}

func (s *Server) render(w http.ResponseWriter, body string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := s.tpl.ExecuteTemplate(w, body, data); err != nil {
		slog.Error("template render", "tpl", body, "err", err)
	}
}

// ---- Auth ----

type loginData struct {
	Error   string
	Next    string
	CSRF    string
	Stage   string // "password" or "totp"
	Pending string // signed pending-2FA token (stage "totp")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	csrf := s.Auth.EnsureCSRF(w, r)
	next := safeNext(r.URL.Query().Get("next"))

	if r.Method != http.MethodPost {
		s.render(w, "login", loginData{Next: next, CSRF: csrf, Stage: "password"})
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.Auth.CheckCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	next = safeNext(r.FormValue("next"))
	ip := clientPeerIP(r)

	if blocked, retry := s.LoginThrottle.Blocked(ip); blocked {
		s.audit(r, r.FormValue("username"), "login", "", "locked")
		s.render(w, "login", loginData{
			Error: fmt.Sprintf("Too many attempts. Try again in %s.", retry.Round(time.Second)),
			Next:  next, CSRF: csrf, Stage: "password",
		})
		return
	}

	// Stage 2 — TOTP code (a pending token proves the password step).
	if pending := r.FormValue("pending"); pending != "" {
		user, ok := s.Auth.VerifyPending(pending)
		if !ok {
			s.render(w, "login", loginData{Error: "Session expired — sign in again.", Next: next, CSRF: csrf, Stage: "password"})
			return
		}
		if !s.Auth.VerifyTOTP(user, r.FormValue("otp")) {
			s.LoginThrottle.Fail(ip)
			s.audit(r, user, "login", "2fa", "fail")
			s.render(w, "login", loginData{Error: "Invalid authentication code.", Next: next, CSRF: csrf, Stage: "totp", Pending: pending})
			return
		}
		s.LoginThrottle.Reset(ip)
		s.Auth.IssueCookie(w, r, user)
		s.audit(r, user, "login", "2fa", "success")
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}

	// Stage 1 — username + password.
	username := r.FormValue("username")
	if err := s.Auth.VerifyPassword(username, r.FormValue("password")); err != nil {
		s.LoginThrottle.Fail(ip)
		s.audit(r, username, "login", "password", "fail")
		s.render(w, "login", loginData{Error: "Invalid username or password.", Next: next, CSRF: csrf, Stage: "password"})
		return
	}
	if s.Auth.TOTPEnabled(username) {
		s.audit(r, username, "login", "password", "2fa-required")
		s.render(w, "login", loginData{Next: next, CSRF: csrf, Stage: "totp", Pending: s.Auth.IssuePending(username)})
		return
	}
	s.LoginThrottle.Reset(ip)
	s.Auth.IssueCookie(w, r, username)
	s.audit(r, username, "login", "password", "success")
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.audit(r, s.user(r), "logout", "", "ok")
	auth.ClearCookie(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- Dashboard ----

type siteRow struct {
	Domain      string
	Aliases     []string
	Filename    string
	Enabled     bool
	Static      bool // static (Root) site vs reverse-proxy site
	Upstreams   []string
	Root        string
	TLS         config.TLSConfig
	ReqsPerMin  uint64
	BytesPerMin uint64
	ErrsPerMin  uint64
	P50         uint32
	P95         uint32
	P99         uint32
	Series      []uint32 // per-second req counts (oldest→newest)
}

type dashboardData struct {
	baseData
	ActiveSites int
	ReqsPerMin  uint64
	BytesPerMin string
	ErrorRate   float64
	Sites       []siteRow
}

func (s *Server) buildSiteRows() (rows []siteRow, totalReqs, totalErrs, totalBytes uint64, active int) {
	sites := s.Store.Snapshot()
	snaps := s.Metrics.SnapshotAll()
	for _, site := range sites {
		snap := snaps[site.Domain]
		series := make([]uint32, len(snap.ReqsPerSec))
		copy(series, snap.ReqsPerSec[:])
		rows = append(rows, siteRow{
			Domain:      site.Domain,
			Aliases:     site.Aliases,
			Filename:    site.Filename,
			Enabled:     site.Enabled,
			Static:      site.Root != "",
			Upstreams:   site.Upstreams,
			Root:        site.Root,
			TLS:         site.TLS,
			ReqsPerMin:  snap.ReqsLast1m,
			BytesPerMin: snap.BytesLast1m,
			ErrsPerMin:  snap.ErrsLast1m,
			P50:         snap.P50,
			P95:         snap.P95,
			P99:         snap.P99,
			Series:      series,
		})
		totalReqs += snap.ReqsLast1m
		totalErrs += snap.ErrsLast1m
		totalBytes += snap.BytesLast1m
		if site.Enabled {
			active++
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Domain < rows[j].Domain })
	return
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	rows, reqs, errs, bytes, active := s.buildSiteRows()
	rate := 0.0
	if reqs > 0 {
		rate = float64(errs) / float64(reqs) * 100
	}
	data := dashboardData{
		baseData:    s.page(w, r, "Dashboard", "dashboard", "dashboard"),
		ActiveSites: active,
		ReqsPerMin:  reqs,
		BytesPerMin: humanBytes(bytes),
		ErrorRate:   rate,
		Sites:       rows,
	}
	s.render(w, "layout", data)
}

func (s *Server) handleSiteRowsPartial(w http.ResponseWriter, r *http.Request) {
	rows, _, _, _, _ := s.buildSiteRows()
	data := struct {
		Sites []siteRow
		CSRF  string
	}{Sites: rows, CSRF: s.Auth.EnsureCSRF(w, r)}
	s.render(w, "site-rows", data)
}

// renderSpark returns an inline SVG sparkline for a per-second series.
// Server-rendered (no client JS, CSP-clean). preserveAspectRatio=none
// lets it stretch to whatever box the CSS gives it.
func renderSpark(series []uint32, w, h int, class string) template.HTML {
	esc := template.HTMLEscapeString(class)
	if len(series) < 2 {
		return template.HTML(`<svg class="` + esc + ` flat" viewBox="0 0 ` +
			strconv.Itoa(w) + ` ` + strconv.Itoa(h) + `"></svg>`)
	}
	var max uint32
	for _, v := range series {
		if v > max {
			max = v
		}
	}
	if max == 0 {
		y := h - 1
		return template.HTML(fmt.Sprintf(
			`<svg class="%s flat" viewBox="0 0 %d %d" preserveAspectRatio="none"><polyline points="0,%d %d,%d"/></svg>`,
			esc, w, h, y, w, y))
	}
	n := len(series)
	var line, area strings.Builder
	fmt.Fprintf(&area, "0,%d ", h)
	for i, v := range series {
		x := float64(i) / float64(n-1) * float64(w)
		y := float64(h) - (float64(v)/float64(max))*(float64(h)-3) - 1
		fmt.Fprintf(&line, "%.1f,%.1f ", x, y)
		fmt.Fprintf(&area, "%.1f,%.1f ", x, y)
	}
	fmt.Fprintf(&area, "%d,%d", w, h)
	return template.HTML(fmt.Sprintf(
		`<svg class="%s" viewBox="0 0 %d %d" preserveAspectRatio="none"><polygon class="area" points="%s"/><polyline points="%s"/></svg>`,
		esc, w, h, strings.TrimSpace(area.String()), strings.TrimSpace(line.String())))
}

// siteFormData backs the add/edit site page. Stats is nil for a new site.
type siteFormData struct {
	baseData
	New   bool
	Site  *config.Site
	Error string
	Saved bool
	Stats *siteStats
}

type siteStats struct {
	TotalRequests uint64
	TotalBytes    string
	TotalErrors   uint64
	ReqsPerMin    uint64
	P50, P95, P99 uint32
	Series        []uint32
	Statuses      []statusRow
}

type statusRow struct {
	Code  int
	Count uint64
	Class string
}

func (s *Server) siteStatsFor(domain string) *siteStats {
	snap := s.Metrics.SnapshotAll()[domain]
	series := make([]uint32, len(snap.ReqsPerSec))
	copy(series, snap.ReqsPerSec[:])
	st := &siteStats{
		TotalRequests: snap.TotalRequests,
		TotalBytes:    humanBytes(snap.TotalBytes),
		TotalErrors:   snap.TotalErrors,
		ReqsPerMin:    snap.ReqsLast1m,
		P50:           snap.P50,
		P95:           snap.P95,
		P99:           snap.P99,
		Series:        series,
	}
	codes := make([]int, 0, len(snap.StatusCounts))
	for c := range snap.StatusCounts {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	for _, c := range codes {
		st.Statuses = append(st.Statuses, statusRow{Code: c, Count: snap.StatusCounts[c], Class: statusClass(c)})
	}
	return st
}

func statusClass(code int) string {
	switch {
	case code >= 500 || code == 0:
		return "s5"
	case code >= 400:
		return "s4"
	case code >= 300:
		return "s3"
	default:
		return "s2"
	}
}

func humanBytes(n uint64) string {
	const k = 1024
	switch {
	case n < k:
		return strconv.FormatUint(n, 10) + " B"
	case n < k*k:
		return strconv.FormatFloat(float64(n)/k, 'f', 1, 64) + " KB"
	case n < k*k*k:
		return strconv.FormatFloat(float64(n)/(k*k), 'f', 1, 64) + " MB"
	default:
		return strconv.FormatFloat(float64(n)/(k*k*k), 'f', 2, 64) + " GB"
	}
}

// ---- Sites list / item ----

func (s *Server) handleSitesList(w http.ResponseWriter, r *http.Request) {
	// /sites POST → create new site
	if r.Method == http.MethodPost {
		s.createOrUpdateSite(w, r, nil)
		return
	}
	// /sites GET → list (redirect to dashboard, which already lists them)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleSiteNew(w http.ResponseWriter, r *http.Request) {
	s.render(w, "layout", siteFormData{
		baseData: s.page(w, r, "Add site", "sites", "site-form"),
		New:      true,
		Site: &config.Site{
			Enabled:             true,
			HTTPToHTTPS:         true,
			WebSocket:           true,
			BlockCommonExploits: true,
			TLS:                 config.TLSConfig{Auto: true},
		},
	})
}

func (s *Server) handleSitesItem(w http.ResponseWriter, r *http.Request) {
	// path is /sites/<filename>[/toggle|/delete]
	path := strings.TrimPrefix(r.URL.Path, "/sites/")
	if path == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	parts := strings.SplitN(path, "/", 2)
	filename := parts[0]

	if strings.ContainsAny(filename, "/\\") || strings.Contains(filename, "..") {
		http.Error(w, "bad filename", http.StatusBadRequest)
		return
	}

	// Find the site.
	var site *config.Site
	for _, candidate := range s.Store.Snapshot() {
		if candidate.Filename == filename {
			site = candidate
			break
		}
	}

	// Sub-action? Both mutate state → POST-only + CSRF-checked.
	if len(parts) == 2 {
		switch parts[1] {
		case "toggle":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if !s.Auth.CheckCSRF(r) {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
			if site == nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			site.Enabled = !site.Enabled
			if _, err := config.SaveSite(s.SitesDir, site); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			s.triggerReload(r.Context())
			result := "disabled"
			if site.Enabled {
				result = "enabled"
			}
			s.audit(r, s.user(r), "site.toggle", filename, result)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		case "delete":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if !s.Auth.CheckCSRF(r) {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
			if err := config.DeleteSite(s.SitesDir, filename); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			s.triggerReload(r.Context())
			s.audit(r, s.user(r), "site.delete", filename, "ok")
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}

	// GET / POST on /sites/<filename>
	if r.Method == http.MethodPost {
		if site == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.createOrUpdateSite(w, r, site)
		return
	}

	if site == nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, "layout", siteFormData{
		baseData: s.page(w, r, site.Domain, "sites", "site-form"),
		Site:     site,
		Saved:    r.URL.Query().Get("saved") == "1",
		Stats:    s.siteStatsFor(site.Domain),
	})
}

func (s *Server) createOrUpdateSite(w http.ResponseWriter, r *http.Request, existing *config.Site) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.Auth.CheckCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	var site config.Site
	if existing != nil {
		site = *existing
	}
	site.Domain = strings.TrimSpace(r.FormValue("domain"))
	site.Aliases = splitWords(r.FormValue("aliases"))
	site.Upstreams = splitLines(r.FormValue("upstreams"))
	site.Root = strings.TrimSpace(r.FormValue("root"))
	site.SPA = r.FormValue("spa") == "on"
	site.Enabled = r.FormValue("enabled") == "on"
	site.HTTPToHTTPS = r.FormValue("http_to_https") == "on"
	site.WebSocket = r.FormValue("websocket") == "on"
	site.BlockCommonExploits = r.FormValue("block_common_exploits") == "on"
	site.TLS.Auto = r.FormValue("tls_auto") == "on"
	site.RateLimit.Enabled = r.FormValue("rl_enabled") == "on"
	if v, err := strconv.Atoi(r.FormValue("rl_rps")); err == nil {
		site.RateLimit.RPS = v
	}
	if v, err := strconv.Atoi(r.FormValue("rl_burst")); err == nil {
		site.RateLimit.Burst = v
	}

	if _, err := config.SaveSite(s.SitesDir, &site); err != nil {
		title := "Add site"
		if existing != nil {
			title = site.Domain
		}
		s.render(w, "layout", siteFormData{
			baseData: s.page(w, r, title, "sites", "site-form"),
			New:      existing == nil,
			Site:     &site,
			Error:    err.Error(),
		})
		return
	}
	s.triggerReload(r.Context())
	action := "site.create"
	if existing != nil {
		action = "site.update"
	}
	s.audit(r, s.user(r), action, site.Domain, "ok")
	http.Redirect(w, r, "/sites/"+site.Filename+"?saved=1", http.StatusSeeOther)
}

func (s *Server) triggerReload(ctx context.Context) {
	if s.ReloadCallback != nil {
		s.ReloadCallback(ctx)
	}
}

func splitWords(s string) []string {
	fields := strings.Fields(s)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func splitLines(s string) []string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// ---- Certs ----

func (s *Server) handleCerts(w http.ResponseWriter, r *http.Request) {
	domains := s.Store.Domains()
	var infos []acme.CertInfo
	if s.ACME != nil {
		infos = s.ACME.ListCerts(domains)
	}
	type data struct {
		baseData
		Certs []acme.CertInfo
	}
	s.render(w, "layout", data{
		baseData: s.base("Certificates", "certs", "certs"),
		Certs:    infos,
	})
}
