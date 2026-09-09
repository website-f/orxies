package secmon

import (
	"strings"
	"time"
)

// parseAuthLog reads the tail of an sshd/PAM log and returns the
// authentication events it contains, oldest first.
//
// Two timestamp formats are supported because both are in the wild:
//
//	2026-09-06T00:01:13.623162+02:00 host sshd[123]: ...   (systemd/rsyslog on Ubuntu 24.04)
//	Sep  6 00:01:13 host sshd[123]: ...                    (traditional syslog)
//
// Getting this wrong is silent — a parser that only knows the classic
// format returns zero events on a modern Ubuntu box and looks like
// "no attacks" rather than "broken parser".
func parseAuthLog(path string, tail int64) ([]Event, error) {
	b, err := readTail(path, tail)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var out []Event
	for _, line := range strings.Split(string(b), "\n") {
		if e, ok := parseAuthLine(line, now); ok {
			out = append(out, e)
		}
	}
	return out, nil
}

// parseAuthLine parses one line. ok is false for anything that is not
// an authentication outcome we track.
func parseAuthLine(line string, now time.Time) (Event, bool) {
	if line == "" {
		return Event{}, false
	}
	// Only sshd lines carry the outcomes we care about; skipping the
	// rest early keeps this cheap over tens of thousands of lines.
	if !strings.Contains(line, "sshd") {
		return Event{}, false
	}

	ts, rest := splitTimestamp(line, now)

	// Narrow to the message after "sshd[pid]: " when present.
	if i := strings.Index(rest, "]: "); i >= 0 {
		rest = rest[i+3:]
	}

	var kind Kind
	switch {
	case strings.HasPrefix(rest, "Failed password"):
		kind = KindFailedPassword
	case strings.HasPrefix(rest, "Invalid user"):
		kind = KindInvalidUser
	case strings.HasPrefix(rest, "Accepted password"):
		kind = KindAcceptedPassword
	case strings.HasPrefix(rest, "Accepted publickey"):
		kind = KindAcceptedKey
	case strings.Contains(rest, "maximum authentication attempts exceeded"):
		kind = KindMaxAuthTries
	default:
		return Event{}, false
	}

	user, ip, port := extractPrincipals(rest)
	if ip == "" {
		return Event{}, false
	}
	return Event{Time: ts, Kind: kind, User: user, IP: ip, Port: port}, true
}

// extractPrincipals pulls the user, source IP and source port out of an
// sshd message. It keys off the "from <ip> port <n>" tail that every
// relevant sshd message shares, and takes the user as the token
// immediately before "from". That one rule covers all the shapes:
//
//	Failed password for root from IP port N ssh2
//	Failed password for invalid user ubuntu from IP port N ssh2
//	Invalid user postgres from IP port N
//	Accepted publickey for root from IP port N ssh2: ED25519 SHA256:...
func extractPrincipals(msg string) (user, ip, port string) {
	f := strings.Fields(msg)
	for i, tok := range f {
		switch tok {
		case "from":
			if i+1 < len(f) {
				ip = f[i+1]
			}
			if i > 0 {
				// Guard against a malformed line where "from" is the
				// first meaningful token.
				cand := f[i-1]
				if cand != "user" && cand != "for" {
					user = cand
				}
			}
		case "port":
			if i+1 < len(f) {
				port = trimNonDigits(f[i+1])
			}
		}
	}
	return user, ip, port
}

// splitTimestamp returns the parsed time and the remainder of the line.
// A zero time is returned (with the line still parsed) when the stamp
// is unrecognisable — an undated event is better than a dropped one.
func splitTimestamp(line string, now time.Time) (time.Time, string) {
	// RFC3339: the first field contains 'T' and starts with a digit.
	if len(line) > 0 && line[0] >= '0' && line[0] <= '9' {
		if sp := strings.IndexByte(line, ' '); sp > 0 {
			stamp, rest := line[:sp], line[sp+1:]
			if t, err := time.Parse(time.RFC3339Nano, stamp); err == nil {
				return t, rest
			}
			// fail2ban style: "2026-09-06 00:05:27,860 ..." — the date
			// and time are two separate fields.
			if t, rest2, ok := parseSpaceDateTime(line); ok {
				return t, rest2
			}
			return time.Time{}, rest
		}
	}

	// Traditional syslog: "Sep  6 00:01:13 host sshd[..]: ..."
	// The year is absent, so assume the current one and step back if
	// that lands in the future (a December log read in January).
	f := strings.SplitN(line, " ", 4)
	// Month, day and time may be separated by a padded double space,
	// which SplitN preserves as an empty field.
	var parts []string
	for _, p := range strings.Split(line, " ") {
		if p != "" {
			parts = append(parts, p)
		}
		if len(parts) == 3 {
			break
		}
	}
	if len(parts) == 3 {
		if t, err := time.Parse("Jan 2 15:04:05", strings.Join(parts, " ")); err == nil {
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			// Re-derive the remainder after the three stamp fields.
			if idx := nthFieldOffset(line, 3); idx > 0 {
				return t, line[idx:]
			}
			return t, line
		}
	}
	if len(f) == 4 {
		return time.Time{}, f[3]
	}
	return time.Time{}, line
}

// parseSpaceDateTime handles "2006-01-02 15:04:05,000 rest..." used by
// fail2ban, returning the time and everything after the stamp.
func parseSpaceDateTime(line string) (time.Time, string, bool) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		return time.Time{}, "", false
	}
	clock := parts[1]
	// Trim fail2ban's ",millis" suffix.
	if i := strings.IndexByte(clock, ','); i >= 0 {
		clock = clock[:i]
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", parts[0]+" "+clock, time.Local)
	if err != nil {
		return time.Time{}, "", false
	}
	return t, parts[2], true
}

// nthFieldOffset returns the byte offset just past the nth
// whitespace-separated field, collapsing runs of spaces.
func nthFieldOffset(s string, n int) int {
	fields, i := 0, 0
	for i < len(s) {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		if i >= len(s) {
			break
		}
		for i < len(s) && s[i] != ' ' {
			i++
		}
		fields++
		if fields == n {
			for i < len(s) && s[i] == ' ' {
				i++
			}
			return i
		}
	}
	return -1
}

func trimNonDigits(s string) string {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	return s[:end]
}
