// Package auth implements admin login for the orxies web UI.
//
// Design:
//   - Admin users live in the global config file (bcrypt password
//     hashes). No separate user DB to maintain.
//   - Sessions are signed cookies (HMAC-SHA256). Stateless on the
//     server side — restart the binary and existing sessions keep
//     working until their expiry. Avoids needing a session store.
//   - 24h session lifetime. Cookie is HttpOnly, SameSite=Lax,
//     Secure when served over HTTPS.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"orxies/internal/config"
)

const (
	cookieName     = "orxies_session"
	csrfCookieName = "orxies_csrf"
	sessionMaxAge  = 24 * time.Hour
	pendingMaxAge  = 5 * time.Minute // window to enter the 2FA code
)

// adminRec is the resolved per-admin credential set.
type adminRec struct {
	hash string // bcrypt password hash
	totp string // base32 TOTP secret, "" = 2FA disabled
}

// Manager holds the active admin list + session signing secret.
type Manager struct {
	admins        map[string]adminRec // username (lower) -> credentials
	secret        []byte
	secureCookies bool // force Secure on cookies even without r.TLS
}

// New builds the Manager. If secret is empty, a persistent one is
// read/written at <dataDir>/secret.key so sessions survive restarts.
func New(g *config.Global, dataDir string) (*Manager, error) {
	if len(g.Admins) == 0 {
		return nil, errors.New("no admins configured — add one to config.yml")
	}
	admins := make(map[string]adminRec, len(g.Admins))
	for _, a := range g.Admins {
		if a.Username == "" || a.PasswordHash == "" {
			return nil, fmt.Errorf("admin %q has empty username or password_hash", a.Username)
		}
		admins[strings.ToLower(a.Username)] = adminRec{
			hash: a.PasswordHash,
			totp: strings.TrimSpace(a.TOTPSecret),
		}
	}

	secret, err := resolveSecret(g.SessionSecret, dataDir)
	if err != nil {
		return nil, err
	}
	return &Manager{admins: admins, secret: secret, secureCookies: g.AdminForceSecureCookie}, nil
}

func resolveSecret(configured, dataDir string) ([]byte, error) {
	if configured != "" {
		if len(configured) < 32 {
			return nil, errors.New("session_secret must be ≥ 32 characters")
		}
		return []byte(configured), nil
	}
	path := filepath.Join(dataDir, "secret.key")
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return b, nil
	}
	// Generate + persist.
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return b, nil
}

// VerifyPassword returns nil if (username, plaintext) match an admin.
func (m *Manager) VerifyPassword(username, password string) error {
	rec, ok := m.admins[strings.ToLower(username)]
	if !ok {
		// Constant-time-ish: still run bcrypt against a throwaway hash
		// so a username probe can't time-distinguish valid users.
		_ = bcrypt.CompareHashAndPassword(
			[]byte("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinval"),
			[]byte(password),
		)
		return errors.New("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(rec.hash), []byte(password)); err != nil {
		return errors.New("invalid credentials")
	}
	return nil
}

// TOTPEnabled reports whether the given admin has 2FA configured.
func (m *Manager) TOTPEnabled(username string) bool {
	rec, ok := m.admins[strings.ToLower(username)]
	return ok && rec.totp != ""
}

// VerifyTOTP checks a 2FA code for the given admin.
func (m *Manager) VerifyTOTP(username, code string) bool {
	rec, ok := m.admins[strings.ToLower(username)]
	if !ok || rec.totp == "" {
		return false
	}
	return VerifyTOTP(rec.totp, code)
}

// secure reports whether cookies should carry the Secure attribute.
func (m *Manager) secure(r *http.Request) bool {
	return m.secureCookies || r.TLS != nil
}

// IssueCookie writes a signed session cookie to w. Caller has already
// verified the password.
func (m *Manager) IssueCookie(w http.ResponseWriter, r *http.Request, username string) {
	exp := time.Now().Add(sessionMaxAge).Unix()
	payload := fmt.Sprintf("%s.%d", strings.ToLower(username), exp)
	sig := m.sign(payload)
	value := base64.RawURLEncoding.EncodeToString([]byte(payload + "." + sig))
	c := &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   m.secure(r),
		Expires:  time.Now().Add(sessionMaxAge),
	}
	http.SetCookie(w, c)
}

// ClearCookie deletes the session cookie.
func ClearCookie(w http.ResponseWriter, r *http.Request) {
	c := &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	}
	http.SetCookie(w, c)
}

// Authenticated returns the username if the request has a valid
// session cookie, or "" if not.
func (m *Manager) Authenticated(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return ""
	}
	parts := strings.SplitN(string(raw), ".", 3)
	if len(parts) != 3 {
		return ""
	}
	username, expStr, sig := parts[0], parts[1], parts[2]
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return ""
	}
	expected := m.sign(username + "." + expStr)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return ""
	}
	if _, ok := m.admins[username]; !ok {
		// Admin was removed from config — invalidate session.
		return ""
	}
	return username
}

func (m *Manager) sign(payload string) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ---- CSRF (signed double-submit) ----
//
// Every mutating request must present a token that appears in BOTH the
// csrf cookie and a form field, and that carries a valid HMAC. The
// signature makes the token self-verifying, so an attacker who can only
// guess or set a raw cookie value (without the secret) cannot forge a
// pair that passes. Defense-in-depth on top of SameSite=Lax.

// EnsureCSRF returns the request's CSRF token, minting and setting a
// signed cookie if one isn't already present/valid. Call on every page
// render that contains a form.
func (m *Manager) EnsureCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookieName); err == nil && m.validCSRF(c.Value) {
		return c.Value
	}
	tok := m.newCSRF()
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   m.secure(r),
	})
	return tok
}

func (m *Manager) newCSRF() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	raw := base64.RawURLEncoding.EncodeToString(b)
	return raw + "." + m.sign("csrf:"+raw)
}

func (m *Manager) validCSRF(v string) bool {
	i := strings.LastIndexByte(v, '.')
	if i <= 0 {
		return false
	}
	raw, sig := v[:i], v[i+1:]
	return hmac.Equal([]byte(sig), []byte(m.sign("csrf:"+raw)))
}

// CheckCSRF validates a mutating request: the csrf_token form field must
// be present, self-verifying, and equal to the csrf cookie. Reads the
// form (safe — callers cap the body first via MaxBody middleware).
func (m *Manager) CheckCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookieName)
	if err != nil || !m.validCSRF(c.Value) {
		return false
	}
	f := r.FormValue("csrf_token")
	if f == "" || !m.validCSRF(f) {
		return false
	}
	return hmac.Equal([]byte(c.Value), []byte(f))
}

// ---- 2FA pending token ----
//
// After a correct password but before the TOTP code, the username is
// carried in a short-lived signed token (5 min) rather than a
// half-authenticated session. It proves "this user just passed the
// password step" without granting any access.

// IssuePending returns a signed token binding username to a 5-minute
// window for completing 2FA.
func (m *Manager) IssuePending(username string) string {
	exp := time.Now().Add(pendingMaxAge).Unix()
	payload := fmt.Sprintf("2fa.%s.%d", strings.ToLower(username), exp)
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "." + m.sign(payload)))
}

// VerifyPending returns the username if tok is a valid, unexpired
// pending-2FA token.
func (m *Manager) VerifyPending(tok string) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return "", false
	}
	parts := strings.SplitN(string(raw), ".", 4) // "2fa", user, exp, sig
	if len(parts) != 4 || parts[0] != "2fa" {
		return "", false
	}
	user, expStr, sig := parts[1], parts[2], parts[3]
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return "", false
	}
	want := m.sign("2fa." + user + "." + expStr)
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return "", false
	}
	if _, ok := m.admins[user]; !ok {
		return "", false
	}
	return user, true
}

// HashPassword is exposed so a future `orxies hash` CLI subcommand
// can generate password_hash values for config.yml.
func HashPassword(plaintext string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Require is middleware that redirects unauthenticated requests to
// /login.
func (m *Manager) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.Authenticated(r) == "" {
			http.Redirect(w, r, "/login?next="+r.URL.Path, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}
