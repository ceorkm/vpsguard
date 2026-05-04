// Package dns watches resolver logs for DNS tunneling and known-bad domains.
package dns

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
	"github.com/nxadm/tail"
)

const Name = "dns"

type Detector struct {
	Paths           []string
	KnownBadDomains []string
	Threshold       int
	Window          time.Duration
}

type domainState struct {
	times []time.Time
	sent  time.Time
}

var defaultPaths = []string{
	"/var/log/syslog",
	"/var/log/messages",
	"/var/log/daemon.log",
}

var domainRE = regexp.MustCompile(`(?i)\b(?:query(?:\[[A-Z0-9]+\])?|reply|gravity blocked|dnsmasq|systemd-resolved)[^A-Za-z0-9._-]+([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)\b`)

func (d *Detector) Name() string { return Name }

func (d *Detector) Run(ctx context.Context, out chan<- *event.Event) error {
	if d.Window <= 0 {
		d.Window = 5 * time.Minute
	}
	if d.Threshold <= 0 {
		d.Threshold = 30
	}
	path := firstExisting(d.Paths)
	if path == "" {
		path = firstExisting(defaultPaths)
	}
	if path == "" {
		<-ctx.Done()
		return nil
	}
	seen := map[string]*domainState{}
	alertedKnownBad := map[string]time.Time{}

	for {
		if ctx.Err() != nil {
			return nil
		}
		t, err := tail.TailFile(path, tail.Config{
			ReOpen:    true,
			Follow:    true,
			MustExist: true,
			Logger:    tail.DiscardingLogger,
		})
		if err != nil {
			return fmt.Errorf("dns: tail %s: %w", path, err)
		}
		stopped := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = t.Stop()
			case <-stopped:
			}
		}()
		for line := range t.Lines {
			if line.Err != nil {
				continue
			}
			d.HandleLine(line.Text, path, seen, alertedKnownBad, out)
		}
		close(stopped)
		t.Cleanup()
		if ctx.Err() != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(30 * time.Second):
		}
	}
}

func (d *Detector) HandleLine(line, path string, seen map[string]*domainState, alertedKnownBad map[string]time.Time, out chan<- *event.Event) {
	q := ExtractDomain(line)
	if q == "" {
		return
	}
	now := time.Now()
	if match := MatchKnownBadDomain(q, d.KnownBadDomains); match != "" {
		last := alertedKnownBad[match]
		if now.Sub(last) > d.Window {
			alertedKnownBad[match] = now
			out <- event.New(event.TypeKnownBadDomain, event.SevCritical, "DNS query for known-bad domain").
				WithSource(Name).
				WithMessage("resolver logs show this VPS queried a domain listed in known_bad_domains").
				WithField("domain", q).
				WithField("matched_domain", match).
				WithField("log", path)
		}
	}
	reason := SuspiciousDomain(q)
	if reason == "" {
		return
	}
	base := baseDomain(q)
	st := seen[base]
	if st == nil {
		st = &domainState{}
		seen[base] = st
	}
	st.times = append(st.times, now)
	cutoff := now.Add(-d.Window)
	filtered := st.times[:0]
	for _, ts := range st.times {
		if !ts.Before(cutoff) {
			filtered = append(filtered, ts)
		}
	}
	st.times = filtered
	if len(st.times) < d.Threshold || now.Sub(st.sent) < d.Window {
		return
	}
	st.sent = now
	out <- event.New(event.TypeDNSAnomaly, event.SevHigh, "Possible DNS tunneling activity").
		WithSource(Name).
		WithMessage("many suspicious long-subdomain DNS queries were observed in resolver logs").
		WithField("domain", q).
		WithField("base_domain", base).
		WithField("reason", reason).
		WithField("queries", len(st.times)).
		WithField("window", d.Window.String()).
		WithField("log", path)
}

func ExtractDomain(line string) string {
	m := domainRE.FindStringSubmatch(line)
	if len(m) < 2 {
		return ""
	}
	return normalizeDomain(m[1])
}

func SuspiciousDomain(domain string) string {
	domain = normalizeDomain(domain)
	if domain == "" {
		return ""
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 3 {
		return ""
	}
	for _, label := range labels[:len(labels)-2] {
		if len(label) >= 50 {
			return "long_label"
		}
		if len(label) >= 32 && highEntropyish(label) {
			return "encoded_subdomain"
		}
	}
	return ""
}

func MatchKnownBadDomain(domain string, known []string) string {
	domain = normalizeDomain(domain)
	// User-configured list first (so user overrides take precedence in
	// telemetry — though both lists fire identically). Fall through to
	// the built-in default list so a fresh install catches the common
	// exfil paths without needing config.
	for _, list := range [][]string{known, BuiltinBadDomains} {
		for _, raw := range list {
			k := normalizeDomain(raw)
			if k == "" {
				continue
			}
			if domain == k || strings.HasSuffix(domain, "."+k) {
				return k
			}
		}
	}
	return ""
}

func highEntropyish(s string) bool {
	var alpha, digit int
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			alpha++
		case r >= '0' && r <= '9':
			digit++
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return alpha >= 10 && digit >= 4
}

func normalizeDomain(s string) string {
	s = strings.ToLower(strings.Trim(strings.TrimSpace(s), "."))
	if strings.ContainsAny(s, "/:@") || !strings.Contains(s, ".") {
		return ""
	}
	return s
}

func baseDomain(domain string) string {
	parts := strings.Split(normalizeDomain(domain), ".")
	if len(parts) <= 2 {
		return strings.Join(parts, ".")
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func firstExisting(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
