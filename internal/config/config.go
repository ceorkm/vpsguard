// Package config loads vpsguard's YAML config.
//
// Default path: /etc/vpsguard/config.yml. Override with --config.
//
// File format:
//
//	server_name: main-vps             # optional; defaults to hostname
//	auth_log: /var/log/auth.log       # optional; auto-detects if omitted
//	healthcheck_url: https://hc-ping.com/abc-123   # optional
//	min_severity: medium               # info|low|medium|high|critical
//	known_bad_ips: [203.0.113.66, 2001:db8:bad::/48]
//	known_bad_domains: [malware.example]
//	telegram:
//	  bot_token: "123456:ABC..."
//	  chat_id:   "987654321"
//	cpu:
//	  threshold: 90
//	  sustain_seconds: 300
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/ceorkm/vpsguard/internal/event"
	"gopkg.in/yaml.v3"
)

const DefaultPath = "/etc/vpsguard/config.yml"

type Config struct {
	ServerName      string         `yaml:"server_name"`
	AuthLog         string         `yaml:"auth_log"`
	HealthcheckURL  string         `yaml:"healthcheck_url"`
	MinSeverity     event.Severity `yaml:"min_severity"`
	Telegram        Telegram       `yaml:"telegram"`
	CPU             CPU            `yaml:"cpu"`
	StateDir        string         `yaml:"state_dir"`
	TrustedIPs      []string       `yaml:"trusted_ips"`
	KnownBadIPs     []string       `yaml:"known_bad_ips"`
	KnownBadDomains []string       `yaml:"known_bad_domains"`

	// Parsed once via TrustedPrefixes() — never set by users in YAML.
	trustedPrefixes  []netip.Prefix
	knownBadPrefixes []netip.Prefix
	knownBadDomains  []string
}

type Telegram struct {
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
}

type CPU struct {
	Threshold      float64 `yaml:"threshold"`
	SustainSeconds int     `yaml:"sustain_seconds"`
}

// Configured reports whether the user has wired up Telegram delivery.
// Both fields must be set together.
func (t Telegram) Configured() bool {
	return usableTelegramValue(t.BotToken) && usableTelegramValue(t.ChatID)
}

func usableTelegramValue(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	upper := strings.ToUpper(s)
	return !strings.Contains(upper, "REPLACE") && !strings.Contains(upper, "YOUR_")
}

// Load reads a config file. If path is empty, DefaultPath is used.
// A missing file is not an error — the agent runs with all defaults
// (stdout-only, no Telegram). This keeps `vpsguard run` useful for
// dev with no setup.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath
	}
	c := &Config{}

	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.applyDefaults()
			return c, nil
		}
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("config: parse %q: %w", path, err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	c.applyDefaults()
	return c, nil
}

// validate catches obvious config mistakes BEFORE the agent starts —
// e.g. a half-configured Telegram block where the user pasted a token
// but forgot the chat ID.
func (c *Config) validate() error {
	if c.Telegram.BotToken != "" && c.Telegram.ChatID == "" {
		return errors.New("config: telegram.bot_token set but telegram.chat_id missing")
	}
	if c.Telegram.BotToken == "" && c.Telegram.ChatID != "" {
		return errors.New("config: telegram.chat_id set but telegram.bot_token missing")
	}
	if c.MinSeverity != "" && !validSeverity(c.MinSeverity) {
		return fmt.Errorf("config: min_severity %q must be one of info|low|medium|high|critical", c.MinSeverity)
	}
	if c.CPU.Threshold < 0 || c.CPU.Threshold > 100 {
		return fmt.Errorf("config: cpu.threshold %.0f out of range (0–100)", c.CPU.Threshold)
	}
	// Pre-parse trusted_ips so users see config errors at startup, not
	// the first time a packet hits the correlator.
	prefixes, err := parseTrustedIPs(c.TrustedIPs)
	if err != nil {
		return err
	}
	c.trustedPrefixes = prefixes
	knownBad, err := parseIPPrefixes("known_bad_ips", c.KnownBadIPs)
	if err != nil {
		return err
	}
	c.knownBadPrefixes = knownBad
	domains, err := normalizeDomains(c.KnownBadDomains)
	if err != nil {
		return err
	}
	c.knownBadDomains = domains
	return nil
}

// parseTrustedIPs accepts both bare IPs (auto-promoted to /32 or /128)
// and full CIDRs. Anything else is a config error.
func parseTrustedIPs(entries []string) ([]netip.Prefix, error) {
	return parseIPPrefixes("trusted_ips", entries)
}

func parseIPPrefixes(field string, entries []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(entries))
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "/") {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("config: %s %q: %w", field, raw, err)
			}
			out = append(out, p)
			continue
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("config: %s %q is neither IP nor CIDR", field, raw)
		}
		bits := 32
		if addr.Is6() && !addr.Is4In6() {
			bits = 128
		}
		out = append(out, netip.PrefixFrom(addr, bits))
	}
	return out, nil
}

func normalizeDomains(entries []string) ([]string, error) {
	out := make([]string, 0, len(entries))
	for _, raw := range entries {
		domain := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "."))
		if domain == "" {
			continue
		}
		if strings.ContainsAny(domain, "/:@ ") || !strings.Contains(domain, ".") {
			return nil, fmt.Errorf("config: known_bad_domains %q must be a bare domain like example.com", raw)
		}
		out = append(out, domain)
	}
	return out, nil
}

// TrustedPrefixes returns the parsed CIDR list. Always populated after
// successful Load().
func (c *Config) TrustedPrefixes() []netip.Prefix {
	return c.trustedPrefixes
}

func (c *Config) KnownBadPrefixes() []netip.Prefix {
	return c.knownBadPrefixes
}

func (c *Config) KnownBadDomainList() []string {
	return c.knownBadDomains
}

// IsTrusted reports whether ip falls within any configured trusted_ips
// entry. Bare-IP entries are matched as /32 or /128.
func (c *Config) IsTrusted(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range c.trustedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (c *Config) applyDefaults() {
	if c.ServerName == "" {
		if h, err := os.Hostname(); err == nil {
			c.ServerName = h
		} else {
			c.ServerName = "unknown"
		}
	}
	if c.AuthLog == "" {
		c.AuthLog = detectAuthLog()
	}
	if c.MinSeverity == "" {
		c.MinSeverity = event.SevMedium
	}
	if c.CPU.Threshold == 0 {
		c.CPU.Threshold = 90
	}
	if c.CPU.SustainSeconds == 0 {
		c.CPU.SustainSeconds = 300
	}
	if c.StateDir == "" {
		c.StateDir = "/var/lib/vpsguard"
	}
}

// detectAuthLog tries the standard paths in priority order.
// Returns empty string if neither exists; the SSH detector will then
// emit an agent.error and the user knows to set auth_log explicitly.
func detectAuthLog() string {
	candidates := []string{
		"/var/log/auth.log", // Debian/Ubuntu
		"/var/log/secure",   // RHEL/CentOS/Fedora/Alma/Rocky
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func validSeverity(s event.Severity) bool {
	switch s {
	case event.SevInfo, event.SevLow, event.SevMedium, event.SevHigh, event.SevCritical:
		return true
	}
	return false
}

// SeverityRank returns an integer ordering for filtering:
// info(0) < low(1) < medium(2) < high(3) < critical(4).
func SeverityRank(s event.Severity) int {
	switch s {
	case event.SevInfo:
		return 0
	case event.SevLow:
		return 1
	case event.SevMedium:
		return 2
	case event.SevHigh:
		return 3
	case event.SevCritical:
		return 4
	}
	return -1
}

// Redact returns a copy of the config safe to log: telegram bot token
// is masked.
func (c *Config) Redact() *Config {
	cp := *c
	if cp.Telegram.BotToken != "" {
		cp.Telegram.BotToken = redactToken(cp.Telegram.BotToken)
	}
	return &cp
}

func redactToken(t string) string {
	// Telegram tokens look like "123456:ABCdef..." — keep the bot ID prefix
	// for log-readability, mask the secret half.
	if i := strings.Index(t, ":"); i >= 0 && len(t) > i+4 {
		return t[:i+1] + strings.Repeat("*", len(t)-i-1)
	}
	return strings.Repeat("*", len(t))
}
