// Package security holds HTTP middleware that hardens the admin UI:
// strict response headers, an optional source-IP allowlist, and a
// request-body size cap. All are pure net/http wrappers with no state,
// so they compose in any order.
package security

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Content-Security-Policy for the admin UI. Everything the UI needs is
// served from its own origin (self-hosted CSS/JS/fonts, inline SVG
// icons), so the policy is strict: no external hosts, no inline script
// or style, no framing. data: is allowed for images only (inline SVG
// icons reference nothing external; data: covers any future favicon).
const csp = "default-src 'self'; " +
	"base-uri 'none'; " +
	"frame-ancestors 'none'; " +
	"form-action 'self'; " +
	"object-src 'none'; " +
	"img-src 'self' data:; " +
	"style-src 'self'; " +
	"script-src 'self'; " +
	"font-src 'self'; " +
	"connect-src 'self'"

// Headers wraps h with a strict security-header set. hsts adds
// Strict-Transport-Security — enable only when the admin UI is actually
// reached over TLS (a TLS terminator in front, or a future TLS admin
// listener); sending it over plain HTTP is pointless and, if the port
// is ever briefly served over HTTP, harmful.
func Headers(h http.Handler, hsts bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", csp)
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), interest-cohort=()")
		hd.Set("Cross-Origin-Opener-Policy", "same-origin")
		hd.Set("Cross-Origin-Resource-Policy", "same-origin")
		if hsts {
			hd.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		h.ServeHTTP(w, r)
	})
}

// ParseCIDRs turns a config list of CIDRs / bare IPs into IPNets. A bare
// IPv4 becomes /32, a bare IPv6 becomes /128.
func ParseCIDRs(items []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		if !strings.Contains(it, "/") {
			if strings.Contains(it, ":") {
				it += "/128"
			} else {
				it += "/32"
			}
		}
		_, n, err := net.ParseCIDR(it)
		if err != nil {
			return nil, fmt.Errorf("bad admin_allow_cidrs entry %q: %w", it, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// IPAllowlist rejects requests whose *direct peer* IP isn't inside one
// of allow. It deliberately ignores X-Forwarded-For — an allowlist that
// trusts a client-supplied header is no allowlist at all. An empty list
// is a passthrough (loopback-only deployments impose no restriction).
func IPAllowlist(allow []*net.IPNet, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(allow) == 0 {
			h.ServeHTTP(w, r)
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if ip := net.ParseIP(host); ip != nil {
			for _, n := range allow {
				if n.Contains(ip) {
					h.ServeHTTP(w, r)
					return
				}
			}
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
	})
}

// MaxBody caps request-body size so a malicious or buggy client can't
// make ParseForm read an unbounded amount into memory.
func MaxBody(n int64, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, n)
		h.ServeHTTP(w, r)
	})
}
