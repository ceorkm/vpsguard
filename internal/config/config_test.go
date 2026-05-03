package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ceorkm/vpsguard/internal/event"
)

func TestLoad_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	body := `server_name: main-vps
auth_log: /var/log/auth.log
healthcheck_url: https://hc-ping.com/abc-123
min_severity: high
telegram:
  bot_token: "123456:ABC"
  chat_id: "987654321"
cpu:
  threshold: 85
  sustain_seconds: 240
known_bad_ips:
  - 203.0.113.66
  - 2001:db8:bad::/48
known_bad_domains:
  - Malware.Example.
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerName != "main-vps" {
		t.Errorf("server_name: %q", c.ServerName)
	}
	if c.AuthLog != "/var/log/auth.log" {
		t.Errorf("auth_log: %q", c.AuthLog)
	}
	if c.HealthcheckURL != "https://hc-ping.com/abc-123" {
		t.Errorf("healthcheck_url: %q", c.HealthcheckURL)
	}
	if c.MinSeverity != event.SevHigh {
		t.Errorf("min_severity: %q", c.MinSeverity)
	}
	if !c.Telegram.Configured() {
		t.Error("telegram should be configured")
	}
	if c.CPU.Threshold != 85 || c.CPU.SustainSeconds != 240 {
		t.Errorf("cpu: %+v", c.CPU)
	}
	if len(c.KnownBadPrefixes()) != 2 {
		t.Errorf("known_bad_ips parsed count: %d", len(c.KnownBadPrefixes()))
	}
	if got := c.KnownBadDomainList(); len(got) != 1 || got[0] != "malware.example" {
		t.Errorf("known_bad_domains normalized: %#v", got)
	}
}

func TestLoad_MissingFileUsesDefaults(t *testing.T) {
	c, err := Load("/nonexistent/path/config.yml")
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if c.ServerName == "" {
		t.Error("expected server_name default to hostname")
	}
	if c.MinSeverity != event.SevMedium {
		t.Errorf("expected min_severity default 'medium', got %q", c.MinSeverity)
	}
	if c.CPU.Threshold != 90 {
		t.Errorf("expected cpu.threshold default 90, got %v", c.CPU.Threshold)
	}
	if c.CPU.SustainSeconds != 300 {
		t.Errorf("expected cpu.sustain_seconds default 300, got %v", c.CPU.SustainSeconds)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte("not valid: yaml: ::"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoad_TelegramHalfConfigured_TokenOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte("telegram:\n  bot_token: \"x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "chat_id missing") {
		t.Errorf("expected chat_id missing error, got %v", err)
	}
}

func TestLoad_TelegramHalfConfigured_ChatOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte("telegram:\n  chat_id: \"y\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "bot_token missing") {
		t.Errorf("expected bot_token missing error, got %v", err)
	}
}

func TestTelegramConfigured_IgnoresPlaceholders(t *testing.T) {
	if (Telegram{BotToken: "REPLACE_WITH_BOT_TOKEN", ChatID: "123"}).Configured() {
		t.Fatal("placeholder bot token should not enable Telegram")
	}
	if (Telegram{BotToken: "123456:ABC", ChatID: "REPLACE_WITH_CHAT_ID"}).Configured() {
		t.Fatal("placeholder chat id should not enable Telegram")
	}
	if !(Telegram{BotToken: "123456:ABC", ChatID: "987654321"}).Configured() {
		t.Fatal("real-looking token and chat id should enable Telegram")
	}
}

func TestLoad_InvalidSeverity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte("min_severity: SEVERE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "min_severity") {
		t.Errorf("expected min_severity error, got %v", err)
	}
}

func TestLoad_InvalidCPUThreshold(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte("cpu:\n  threshold: 150\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("expected threshold range error, got %v", err)
	}
}

func TestSeverityRank(t *testing.T) {
	if SeverityRank(event.SevInfo) >= SeverityRank(event.SevHigh) {
		t.Error("info should rank lower than high")
	}
	if SeverityRank(event.SevCritical) <= SeverityRank(event.SevHigh) {
		t.Error("critical should rank higher than high")
	}
	if SeverityRank("bogus") != -1 {
		t.Error("unknown severity should rank -1")
	}
}

func TestLoad_TrustedIPs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	body := `trusted_ips:
  - 102.89.34.12
  - 10.0.0.0/8
  - 2001:db8::1
  - 2001:db8::/32
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	prefixes := c.TrustedPrefixes()
	if len(prefixes) != 4 {
		t.Fatalf("got %d trusted prefixes, want 4", len(prefixes))
	}

	// Bare IPv4 -> /32
	if prefixes[0].Bits() != 32 {
		t.Errorf("bare IPv4 should be /32, got /%d", prefixes[0].Bits())
	}
	// Bare IPv6 -> /128
	if prefixes[2].Bits() != 128 {
		t.Errorf("bare IPv6 should be /128, got /%d", prefixes[2].Bits())
	}

	// Containment checks
	if !c.IsTrusted("102.89.34.12") {
		t.Error("exact bare IP not matched")
	}
	if !c.IsTrusted("10.5.6.7") {
		t.Error("IP within /8 not matched")
	}
	if c.IsTrusted("11.5.6.7") {
		t.Error("IP outside /8 incorrectly matched")
	}
	if !c.IsTrusted("2001:db8::1") {
		t.Error("IPv6 not matched")
	}
	if c.IsTrusted("not-an-ip") {
		t.Error("bogus string should not match")
	}
}

func TestLoad_TrustedIPsInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	body := "trusted_ips:\n  - bogus.entry\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "trusted_ips") {
		t.Errorf("expected trusted_ips parse error, got %v", err)
	}
}

func TestLoad_KnownBadIPsInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	body := "known_bad_ips:\n  - bad.ip\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "known_bad_ips") {
		t.Errorf("expected known_bad_ips parse error, got %v", err)
	}
}

func TestLoad_KnownBadDomainsInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	body := "known_bad_domains:\n  - https://evil.example/path\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "known_bad_domains") {
		t.Errorf("expected known_bad_domains parse error, got %v", err)
	}
}

func TestStateDirDefault(t *testing.T) {
	c, err := Load("/nonexistent/config.yml")
	if err != nil {
		t.Fatal(err)
	}
	if c.StateDir != "/var/lib/vpsguard" {
		t.Errorf("default state_dir wrong: %q", c.StateDir)
	}
}

func TestRedact(t *testing.T) {
	c := &Config{Telegram: Telegram{BotToken: "123456:ABCdefSECRET", ChatID: "111"}}
	r := c.Redact()
	if strings.Contains(r.Telegram.BotToken, "ABCdef") || strings.Contains(r.Telegram.BotToken, "SECRET") {
		t.Errorf("redact leaked secret: %q", r.Telegram.BotToken)
	}
	if !strings.HasPrefix(r.Telegram.BotToken, "123456:") {
		t.Errorf("redact should keep bot id prefix, got %q", r.Telegram.BotToken)
	}
	// Original must be untouched.
	if c.Telegram.BotToken != "123456:ABCdefSECRET" {
		t.Errorf("redact mutated original: %q", c.Telegram.BotToken)
	}
}
