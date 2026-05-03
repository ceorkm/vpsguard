// Package logpattern tails common VPS service logs and emits brute-force
// events for mail, web, and control-panel authentication failures.
package logpattern

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
	"github.com/nxadm/tail"
)

const Name = "logpattern"

type Detector struct {
	NameLabel string
	Paths     []string
	Patterns  []*regexp.Regexp
	Service   string
	Threshold int
	Window    time.Duration
}

type state struct {
	times []time.Time
	sent  time.Time
}

func DefaultDetectors() []Detector {
	return []Detector{
		{
			NameLabel: "mail",
			Service:   "mail",
			Paths: []string{
				"/var/log/mail.log",
				"/var/log/maillog",
			},
			Patterns: compileAll(
				`(?i)(dovecot|imap|pop3).*auth.*failed.*rip=(?P<ip>[0-9a-fA-F:.]+)`,
				`(?i)(postfix|sasl).*authentication failed.*\[(?P<ip>[0-9a-fA-F:.]+)\]`,
				`(?i)authentication failure.*rhost=(?P<ip>[0-9a-fA-F:.]+)`,
			),
			Threshold: 20,
			Window:    5 * time.Minute,
		},
		{
			NameLabel: "web",
			Service:   "web",
			Paths: []string{
				"/var/log/nginx/access.log",
				"/var/log/apache2/access.log",
				"/var/log/httpd/access_log",
			},
			Patterns: compileAll(
				`^(?P<ip>[0-9a-fA-F:.]+)\s+.*"(POST|GET) [^"]*(wp-login\.php|xmlrpc\.php|/login|/admin)[^"]*"\s+(401|403|404)`,
			),
			Threshold: 30,
			Window:    5 * time.Minute,
		},
		{
			NameLabel: "panel",
			Service:   "control_panel",
			Paths: []string{
				"/usr/local/hestia/log/auth.log",
				"/usr/local/cpanel/logs/login_log",
				"/www/server/panel/logs/request.log",
				"/usr/local/CyberCP/logs/access.log",
			},
			Patterns: compileAll(
				`(?i)(failed|invalid|login error|authentication failure).*from\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]{3,})`,
				`^(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,}).*(?i)(failed|invalid|login error|authentication failure)`,
			),
			Threshold: 10,
			Window:    5 * time.Minute,
		},
	}
}

func (d Detector) Name() string {
	if d.NameLabel == "" {
		return Name
	}
	return Name + "." + d.NameLabel
}

func (d Detector) Run(ctx context.Context, out chan<- *event.Event) error {
	if d.Window <= 0 {
		d.Window = 5 * time.Minute
	}
	if d.Threshold <= 0 {
		d.Threshold = 20
	}
	path := firstExisting(d.Paths)
	if path == "" {
		<-ctx.Done()
		return nil
	}
	t, err := tail.TailFile(path, tail.Config{
		ReOpen:    true,
		Follow:    true,
		MustExist: true,
		Logger:    tail.DiscardingLogger,
	})
	if err != nil {
		return fmt.Errorf("logpattern: tail %s: %w", path, err)
	}
	defer t.Cleanup()
	go func() {
		<-ctx.Done()
		_ = t.Stop()
	}()
	seen := map[string]*state{}
	for line := range t.Lines {
		if line.Err != nil {
			continue
		}
		d.handleLine(line.Text, path, seen, out)
	}
	return nil
}

func (d Detector) handleLine(line, path string, seen map[string]*state, out chan<- *event.Event) {
	ip := d.matchIP(line)
	if ip == "" {
		return
	}
	now := time.Now()
	st := seen[ip]
	if st == nil {
		st = &state{}
		seen[ip] = st
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
	out <- event.New(event.TypeServiceBruteforce, event.SevHigh,
		"Service brute-force attack detected").
		WithSource(d.Name()).
		WithMessage("repeated failed authentication attempts in service logs").
		WithField("service", d.Service).
		WithField("ip", ip).
		WithField("log", path).
		WithField("failed_attempts", len(st.times)).
		WithField("window", d.Window.String())
}

func (d Detector) matchIP(line string) string {
	for _, re := range d.Patterns {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		for i, name := range re.SubexpNames() {
			if name == "ip" && i < len(m) {
				return strings.Trim(m[i], "[]")
			}
		}
	}
	return ""
}

func firstExisting(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func compileAll(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}

func ScanReader(ctx context.Context, scanner *bufio.Scanner, d Detector, out chan<- *event.Event) error {
	if scanner == nil {
		return errors.New("nil scanner")
	}
	seen := map[string]*state{}
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		d.handleLine(scanner.Text(), "stdin", seen, out)
	}
	return scanner.Err()
}
