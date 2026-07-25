package auth

// TOTP (RFC 6238) implemented inline with the standard library only —
// no third-party dependency, so the Docker build stays self-contained
// (the repo ships no go.sum; the image runs `go mod tidy`).
//
// Defaults match every authenticator app (Google Authenticator, Authy,
// 1Password): SHA1, 6 digits, 30-second period, ±1 step clock skew.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpDigits = 6
	totpPeriod = 30 // seconds
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a fresh base32-encoded 160-bit secret suitable
// for pasting into config.yml (admins[].totp_secret).
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

func normalizeB32(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	return s
}

func totpAt(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(normalizeB32(secret))
	if err != nil {
		return "", fmt.Errorf("invalid TOTP secret: %w", err)
	}
	return hotp(key, uint64(t.Unix())/totpPeriod), nil
}

func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f) << 24) |
		(uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) |
		uint32(sum[off+3])
	return fmt.Sprintf("%0*d", totpDigits, code%1_000_000)
}

// CurrentCode returns the TOTP code valid for secret at this instant.
// Handy for operators confirming a freshly-added secret, and exercised
// by tests.
func CurrentCode(secret string) (string, error) {
	return totpAt(secret, time.Now())
}

// VerifyTOTP reports whether code is valid for secret right now,
// tolerating one 30s step of clock drift in each direction. The code
// comparison is constant-time.
func VerifyTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	now := time.Now()
	for _, skew := range []time.Duration{0, -totpPeriod * time.Second, totpPeriod * time.Second} {
		want, err := totpAt(secret, now.Add(skew))
		if err != nil {
			return false
		}
		if hmac.Equal([]byte(want), []byte(code)) {
			return true
		}
	}
	return false
}

// TOTPURI builds an otpauth:// URI that authenticator apps import (and
// that a QR encoder can render). issuer is the label shown in the app.
func TOTPURI(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", normalizeB32(secret))
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprintf("%d", totpDigits))
	v.Set("period", fmt.Sprintf("%d", totpPeriod))
	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?" + v.Encode()
}
