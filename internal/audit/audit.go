// Package audit records admin actions (logins, site create/update/
// delete/toggle) to an append-only JSON-lines file. For a system that
// controls domains and TLS on a live server, "who changed what, from
// where, and when" is not optional.
package audit

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// Logger appends one JSON object per line. A nil *Logger is a safe
// no-op, so call sites never need a nil guard.
type Logger struct {
	mu sync.Mutex
	f  *os.File
}

// Open opens (creating if needed) the audit log at path for appending.
func Open(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{f: f}, nil
}

// Record is one audit line.
type Record struct {
	Time   string `json:"time"`
	User   string `json:"user,omitempty"`
	IP     string `json:"ip"`
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Result string `json:"result"`
}

// Log writes one audit record. It also mirrors to slog so operators
// tailing container logs see the same events.
func (l *Logger) Log(r *http.Request, user, action, target, result string) {
	rec := Record{
		Time:   time.Now().UTC().Format(time.RFC3339),
		User:   user,
		IP:     clientIP(r),
		Action: action,
		Target: target,
		Result: result,
	}
	slog.Info("audit",
		"user", rec.User, "ip", rec.IP,
		"action", rec.Action, "target", rec.Target, "result", rec.Result)
	if l == nil {
		return
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	b = append(b, '\n')
	l.mu.Lock()
	_, _ = l.f.Write(b)
	l.mu.Unlock()
}

// Close flushes and closes the underlying file.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
