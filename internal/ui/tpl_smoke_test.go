package ui

import (
	"bytes"
	"testing"
	"time"

	"orxies/internal/deploy"
	"orxies/internal/store"
)

// Renders service-detail with a backup row so template funcs (icon, bytes)
// and the Backups section are exercised end-to-end.
func TestServiceDetailBackupTemplate(t *testing.T) {
	s, err := New(&Server{})
	if err != nil {
		t.Fatal(err)
	}
	type data struct {
		baseData
		Service   *store.Service
		Host      string
		Busy      bool
		Backups   []deploy.Backup
		BackupsOK bool
	}
	d := data{
		Service:   &store.Service{ID: 1, Name: "pg", Engine: "postgres", Mode: "managed", Status: "running"},
		Host:      "orxies-svc-pg",
		BackupsOK: true,
		Backups:   []deploy.Backup{{Name: "20260728-101500.sql", Size: 4096, ModTime: time.Now()}},
	}
	var buf bytes.Buffer
	if err := s.tpl.ExecuteTemplate(&buf, "service-detail", d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Back up now", "20260728-101500.sql", "4.0 KB", "Restore", "backup-download"} {
		if !bytes.Contains(buf.Bytes(), []byte(want)) {
			t.Errorf("rendered output missing %q", want)
		}
	}
}
