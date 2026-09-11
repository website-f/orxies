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

// EdgeHeaders is the baseline security-header set applied to every
// PUBLIC response the proxy serves — proxied and static alike.
//
// Why here rather than per-site config: these are the headers you want
// on everything, and anything you have to remember to add per site is a
// header some site will be missing. Per-site custom_headers still win,
// because they're merged over this map (see MergeEdgeHeaders).
//
// Two deliberate omissions:
//
//   - Content-Security-Policy. A blind CSP breaks real applications —
//     these upstreams are React/Inertia apps with inline bootstrap
//     data, Vite assets, and a Leaflet map pulling tiles from a third
//     party. A policy tight enough to be worth having has to be written
//     per app and tested against it, so it's left as an opt-in via a
//     site's custom_headers rather than shipped broken by default.
//
//   - Strict-Transport-Security. Handled separately in the router,
//     because it must only ever be sent over TLS — see EdgeHSTS.
func EdgeHeaders() map[string]string {
	return map[string]string{
		// Stop the browser second-guessing declared content types,
		// which is how a user-uploaded image gets executed as script.
		"X-Content-Type-Options": "nosniff",
		// SAMEORIGIN rather than DENY: DENY would also block the site
		// framing its own pages, which some upstreams legitimately do.
		"X-Frame-Options": "SAMEORIGIN",
		// Send the origin, not the full path, to third parties — paths
		// leak order IDs, tokens and search terms via Referer.
		"Referrer-Policy": "strict-origin-when-cross-origin",
		// Deny powerful device APIs no upstream here asks for.
		//
		// geolocation=(self), NOT geolocation=(). The empty allowlist denies
		// the API to EVERY origin including the site's own page, so
		// navigator.geolocation fails with PERMISSION_DENIED no matter what
		// the visitor allows in the browser. RizqMall's "stores near you" map
		// asks for a fix from its own page, and it was reporting "location is
		// blocked, allow it in your browser" to people who had already allowed
		// it. (self) keeps third-party frames denied while letting a site's own
		// page ask.
		"Permissions-Policy": "geolocation=(self), microphone=(), camera=(), payment=(), usb=()",
		// Legacy but harmless, and still honoured by some proxies.
		"X-Permitted-Cross-Domain-Policies": "none",
	}
}

// MergeEdgeHeaders returns the baseline set with a site's custom
// headers layered on top, so a site can override or add to it.
//
// Returning ONE merged map matters: applying baseline and custom
// separately would emit duplicate headers for keys present in both,
// and browsers treat duplicated security headers inconsistently.
func MergeEdgeHeaders(custom map[string]string) map[string]string {
	out := EdgeHeaders()
	for k, v := range custom {
		out[k] = v
	}
	return out
}

// EdgeHSTS is the Strict-Transport-Security value for public HTTPS
// responses, or "" when HSTS should not be sent.
//
// Deliberately conservative:
//
//   - 180 days, not the two years a preload submission wants. HSTS is
//     effectively irreversible for as long as the max-age you last
//     served, so a shorter window keeps a mistake recoverable.
//   - NO includeSubDomains. It would force HTTPS on every subdomain of
//     the host, including ones whose certificate isn't issued yet — on
//     this deployment ws.staging.rizqmall.com has no DNS record and its
//     ACME challenge fails, so including subdomains would make that
//     name permanently unreachable in any browser that saw the header.
//   - NO preload, which is a one-way door requiring both of the above.
//
// Widen these once every subdomain reliably serves TLS.
func EdgeHSTS(isTLS bool) string {
	if !isTLS {
		return "" // pointless over plaintext, and harmful if a host is ever HTTP-only
	}
	return "max-age=15552000"
}
