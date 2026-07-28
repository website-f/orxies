package ui

import (
	"context"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"

	"orxies/internal/deploy"
	"orxies/internal/store"
)

// ---- svc log helpers (async provisioning output) ----

func (s *Server) svcLog(id int64) *logBuf {
	s.projMu.Lock()
	defer s.projMu.Unlock()
	lb := s.svcLogs[id]
	if lb == nil {
		lb = &logBuf{}
		s.svcLogs[id] = lb
	}
	return lb
}
func (s *Server) setSvcBusy(id int64, v bool) {
	s.projMu.Lock()
	s.svcBusy[id] = v
	s.projMu.Unlock()
}
func (s *Server) isSvcBusy(id int64) bool {
	s.projMu.Lock()
	defer s.projMu.Unlock()
	return s.svcBusy[id]
}

// TriggerProvision starts an async provision of a managed service.
func (s *Server) TriggerProvision(id int64) {
	if s.isSvcBusy(id) {
		return
	}
	lb := s.svcLog(id)
	lb.reset()
	io.WriteString(lb, "Provisioning service...\n")
	s.setSvcBusy(id, true)
	go func() {
		defer s.setSvcBusy(id, false)
		if err := s.Deploy.ProvisionService(context.Background(), id, lb); err != nil {
			io.WriteString(lb, "\n=== PROVISION FAILED: "+err.Error()+" ===\n")
		} else {
			io.WriteString(lb, "\n=== SERVICE READY ===\n")
		}
	}()
}

// ---- list ----

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/services" {
		http.NotFound(w, r)
		return
	}
	svcs, _ := s.DB.ListServices()
	type row struct {
		*store.Service
		Busy bool
	}
	rows := make([]row, 0, len(svcs))
	for _, sv := range svcs {
		rows = append(rows, row{Service: sv, Busy: s.isSvcBusy(sv.ID)})
	}
	type data struct {
		baseData
		Services []row
	}
	s.render(w, "layout", data{
		baseData: s.page(w, r, "Services", "services", "services"),
		Services: rows,
	})
}

// ---- new / create ----

func (s *Server) handleServiceNew(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.createService(w, r)
		return
	}
	s.renderServiceForm(w, r, "", map[string]string{"mode": "managed", "engine": "postgres"})
}

type serviceFormData struct {
	baseData
	Error   string
	Values  map[string]string
	Engines []string
}

func (s *Server) renderServiceForm(w http.ResponseWriter, r *http.Request, errMsg string, vals map[string]string) {
	s.render(w, "layout", serviceFormData{
		baseData: s.page(w, r, "New service", "services", "service-form"),
		Error:    errMsg,
		Values:   vals,
		Engines:  []string{"postgres", "mysql", "redis"},
	})
}

func (s *Server) createService(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.Auth.CheckCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	vals := map[string]string{
		"name":   strings.TrimSpace(r.FormValue("name")),
		"mode":   r.FormValue("mode"),
		"engine": r.FormValue("engine"),
		"url":    strings.TrimSpace(r.FormValue("url")),
	}
	svc := &store.Service{Name: vals["name"], Engine: vals["engine"], Mode: vals["mode"]}
	if svc.Mode == "" {
		svc.Mode = "managed"
	}
	if svc.Name == "" || svc.Engine == "" {
		s.renderServiceForm(w, r, "Name and engine are required.", vals)
		return
	}
	if svc.Mode == "external" && vals["url"] == "" {
		s.renderServiceForm(w, r, "External services need a connection URL.", vals)
		return
	}
	if svc.Mode == "external" {
		svc.Status = "external"
		s.Deploy.SetExternalCreds(svc, vals["url"]) // encrypts into svc.CredsEnc
	}
	if err := s.DB.CreateService(svc); err != nil {
		s.renderServiceForm(w, r, err.Error(), vals)
		return
	}
	s.audit(r, s.user(r), "service.create", svc.Name, svc.Mode)
	if svc.Mode == "managed" {
		s.TriggerProvision(svc.ID)
	}
	http.Redirect(w, r, "/services/"+strconv.FormatInt(svc.ID, 10), http.StatusSeeOther)
}

// ---- item + actions ----

func (s *Server) handleServiceItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/services/")
	parts := strings.SplitN(rest, "/", 2)
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	svc, err := s.DB.GetService(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 2 {
		switch parts[1] {
		case "provision":
			if !s.postCSRF(w, r) {
				return
			}
			s.TriggerProvision(id)
			s.audit(r, s.user(r), "service.provision", svc.Name, "started")
			http.Redirect(w, r, "/services/"+parts[0], http.StatusSeeOther)
		case "remove":
			if !s.postCSRF(w, r) {
				return
			}
			if err := s.Deploy.RemoveService(r.Context(), id); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			s.audit(r, s.user(r), "service.remove", svc.Name, "ok")
			http.Redirect(w, r, "/services", http.StatusSeeOther)
		case "logs":
			out := s.svcLog(id).String()
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			io.WriteString(w, template.HTMLEscapeString(out))
		case "backup":
			if !s.postCSRF(w, r) {
				return
			}
			name, err := s.Deploy.BackupService(r.Context(), id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			s.audit(r, s.user(r), "service.backup", svc.Name, name)
			http.Redirect(w, r, "/services/"+parts[0], http.StatusSeeOther)
		case "restore":
			if !s.postCSRF(w, r) {
				return
			}
			name := strings.TrimSpace(r.FormValue("name"))
			if err := s.Deploy.RestoreService(r.Context(), id, name); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			s.audit(r, s.user(r), "service.restore", svc.Name, name)
			http.Redirect(w, r, "/services/"+parts[0], http.StatusSeeOther)
		case "backup-download":
			name := strings.TrimSpace(r.URL.Query().Get("name"))
			path, err := s.Deploy.BackupPath(id, name)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/sql")
			w.Header().Set("Content-Disposition", "attachment; filename=\""+svc.Engine+"-"+name+"\"")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			http.ServeFile(w, r, path)
		default:
			http.NotFound(w, r)
		}
		return
	}
	backups, _ := s.Deploy.ListBackups(id)
	type data struct {
		baseData
		Service   *store.Service
		Host      string
		Busy      bool
		Backups   []deploy.Backup
		BackupsOK bool
	}
	s.render(w, "layout", data{
		baseData:  s.page(w, r, svc.Name, "services", "service-detail"),
		Service:   svc,
		Host:      deploy.ServiceName(svc.Name),
		Busy:      s.isSvcBusy(id),
		Backups:   backups,
		BackupsOK: svc.Mode == "managed" && (svc.Engine == "postgres" || svc.Engine == "mysql"),
	})
}

// postCSRF enforces POST + CSRF for an action, writing the error response
// itself and returning false if the request should not proceed.
func (s *Server) postCSRF(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if !s.Auth.CheckCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return false
	}
	return true
}
