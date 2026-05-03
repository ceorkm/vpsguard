package filewatch

import (
	"os"
	"strings"
)

// cronScanResult is the outcome of inspecting a cron file's contents
// for the kinds of one-liner payloads attackers use for persistence.
// Empty Reason means nothing matched.
type cronScanResult struct {
	Reason  string // short tag, used as event field
	Snippet string // up to ~120 chars of the offending command, redacted
}

// scanCronContent reads a cron file or drop-in and returns the first
// pattern that looks like an attacker one-liner. The intent is high
// recall on the patterns Kinsing, TeamTNT, Diicot, and the rest of
// the public miner/botnet families ship with — at the expense of
// occasional false positives on weird-but-legit cron jobs. False
// positives are a one-tap dismiss in Telegram; missed compromise is
// not.
func scanCronContent(path string) cronScanResult {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return cronScanResult{}
	}
	body := string(b)
	low := strings.ToLower(body)

	// Pipe-to-shell remote-payload patterns. The classic "drop a
	// payload via curl, pipe straight into bash" the bulk of crypto-
	// miner cron jobs use.
	pipeShells := []struct{ tag, needle string }{
		{"curl_pipe_shell", "curl"},
		{"wget_pipe_shell", "wget"},
		{"fetch_pipe_shell", "fetch"},
	}
	for _, p := range pipeShells {
		if !strings.Contains(low, p.needle) {
			continue
		}
		// Only flag if the command also pipes to a shell — otherwise
		// "curl -o /var/log/x" is fine.
		if strings.Contains(low, "|sh") || strings.Contains(low, "| sh") ||
			strings.Contains(low, "|bash") || strings.Contains(low, "| bash") ||
			strings.Contains(low, "|zsh") || strings.Contains(low, "| zsh") {
			return cronScanResult{Reason: p.tag, Snippet: snippet(body, p.needle)}
		}
	}

	// Base64 + decode + execute — classic obfuscation. Heuristic:
	// "base64 -d" or "base64 --decode" followed (anywhere) by a pipe
	// to sh/bash.
	if (strings.Contains(low, "base64 -d") || strings.Contains(low, "base64 --decode") || strings.Contains(low, "base64 -d -")) &&
		(strings.Contains(low, "|sh") || strings.Contains(low, "| sh") ||
			strings.Contains(low, "|bash") || strings.Contains(low, "| bash")) {
		return cronScanResult{Reason: "base64_decode_pipe_shell", Snippet: snippet(body, "base64")}
	}

	// /dev/tcp/host/port reverse shells in cron — extremely rare to be
	// legit.
	if strings.Contains(low, "/dev/tcp/") {
		return cronScanResult{Reason: "dev_tcp_reverse_shell", Snippet: snippet(body, "/dev/tcp/")}
	}

	// Direct execve of a binary in a writable temp dir.
	for _, dir := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/lock/"} {
		if strings.Contains(body, dir) {
			return cronScanResult{Reason: "exec_from_tmp", Snippet: snippet(body, dir)}
		}
	}

	// Inline python/perl/ruby reverse-shell one-liners. The specific
	// imports show up in the well-known revshell-cheatsheet payloads
	// (PayloadsAllTheThings, GTFObins).
	for _, needle := range []string{
		"python -c \"import socket",
		"python3 -c \"import socket",
		"perl -e 'use socket",
		"perl -e \"use socket",
		"ruby -rsocket",
		"socat exec:",
		"nc -e ",
		"nc -c ",
		"ncat --exec",
		"ncat -e ",
	} {
		if strings.Contains(low, needle) {
			return cronScanResult{Reason: "interpreter_reverse_shell", Snippet: snippet(body, strings.TrimRight(needle, " "))}
		}
	}

	return cronScanResult{}
}

// snippet returns up to ~120 chars of the line containing `needle`,
// stripped to one line for human-readable Telegram output.
func snippet(body, needle string) string {
	idx := strings.Index(strings.ToLower(body), strings.ToLower(needle))
	if idx < 0 {
		return ""
	}
	// Find line bounds.
	start := idx
	for start > 0 && body[start-1] != '\n' {
		start--
	}
	end := idx + len(needle)
	for end < len(body) && body[end] != '\n' {
		end++
	}
	line := strings.TrimSpace(body[start:end])
	if len(line) > 120 {
		line = line[:117] + "..."
	}
	return line
}
