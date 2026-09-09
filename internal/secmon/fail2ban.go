package secmon

import (
	"strings"
	"time"
)

// parseFail2banLog reads the tail of fail2ban's log and returns ban and
// unban actions, oldest first. Lines look like:
//
//	2026-09-06 00:05:27,860 fail2ban.actions        [1544044]: NOTICE  [sshd] Ban 195.178.110.227
//	2026-09-06 00:05:31,913 fail2ban.actions        [1544044]: NOTICE  [sshd] Unban 37.111.53.110
//
// Only actions are extracted; fail2ban's "Found" lines duplicate what
// the sshd log already tells us, and counting both would double-report
// the same attempt.
func parseFail2banLog(path string, tail int64) ([]Event, error) {
	b, err := readTail(path, tail)
	if err != nil {
		return nil, err
	}
	var out []Event
	for _, line := range strings.Split(string(b), "\n") {
		if e, ok := parseFail2banLine(line); ok {
			out = append(out, e)
		}
	}
	return out, nil
}

func parseFail2banLine(line string) (Event, bool) {
	if line == "" {
		return Event{}, false
	}
	var kind Kind
	switch {
	case strings.Contains(line, " Ban "):
		kind = KindBan
	case strings.Contains(line, " Unban "):
		kind = KindUnban
	case strings.Contains(line, " Restore Ban "):
		// Emitted when fail2ban restarts and reinstates a live ban.
		// It is a real active ban, so treat it as one.
		kind = KindBan
	default:
		return Event{}, false
	}

	ts := time.Time{}
	if t, _, ok := parseSpaceDateTime(line); ok {
		ts = t
	}

	// The IP is the final field; the jail is the bracketed token just
	// before the action word.
	f := strings.Fields(line)
	if len(f) == 0 {
		return Event{}, false
	}
	ip := f[len(f)-1]
	if !looksLikeIP(ip) {
		return Event{}, false
	}

	jail := ""
	for _, tok := range f {
		if len(tok) > 2 && tok[0] == '[' && tok[len(tok)-1] == ']' {
			inner := tok[1 : len(tok)-1]
			// Skip the "[pid]:" field, which is all digits.
			if !allDigits(inner) {
				jail = inner
			}
		}
	}
	return Event{Time: ts, Kind: kind, IP: ip, Jail: jail}, true
}

// looksLikeIP is a cheap shape check — enough to reject log prose
// without pulling in net.ParseIP for every line.
func looksLikeIP(s string) bool {
	if s == "" {
		return false
	}
	digits, dots, colons := 0, 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			digits++
		case c == '.':
			dots++
		case c == ':':
			colons++
		case (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
			// hex digits are valid in IPv6
		default:
			return false
		}
	}
	if colons >= 2 {
		return true // IPv6
	}
	return dots == 3 && digits >= 4
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
