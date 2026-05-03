// Package ssh implements an auth.log tail-based SSH event detector.
// Patterns derived from Fail2Ban filter.d/sshd.conf (regexes describe
// OpenSSH log facts and are safely portable across licenses).
package ssh

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/ceorkm/vpsguard/internal/event"
	"github.com/nxadm/tail"
)

const Name = "ssh"

// Pattern set, ordered by hit frequency (most common first).
// Each must contain named groups <user> and <ip> where applicable.
var patterns = []struct {
	re       *regexp.Regexp
	typ      string
	severity event.Severity
	title    string
	method   string
}{
	{
		// Fail2Ban: ^Failed \S+ for (?:invalid user )?<F-USER>... from <HOST>
		re:       regexp.MustCompile(`sshd\[\d+\]:\s+Failed (?:password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+`),
		typ:      event.TypeSSHLoginFailed,
		severity: event.SevLow,
		title:    "SSH login failed",
		method:   "password/publickey",
	},
	{
		// Fail2Ban: ^[iI](?:llegal|nvalid) user
		re:       regexp.MustCompile(`sshd\[\d+\]:\s+[Ii]nvalid user (?P<user>\S+) from (?P<ip>\S+)`),
		typ:      event.TypeSSHInvalidUser,
		severity: event.SevLow,
		title:    "SSH login attempt for invalid user",
	},
	{
		// Successful password login
		re:       regexp.MustCompile(`sshd\[\d+\]:\s+Accepted password for (?P<user>\S+) from (?P<ip>\S+) port \d+`),
		typ:      event.TypeSSHLoginSuccess,
		severity: event.SevMedium, // upgraded to high in correlator if root or new IP
		title:    "SSH login (password)",
		method:   "password",
	},
	{
		// Successful publickey login
		re:       regexp.MustCompile(`sshd\[\d+\]:\s+Accepted publickey for (?P<user>\S+) from (?P<ip>\S+) port \d+`),
		typ:      event.TypeSSHLoginSuccess,
		severity: event.SevMedium,
		title:    "SSH login (publickey)",
		method:   "publickey",
	},
	{
		// Max auth attempts exceeded — strong brute-force signal on its own
		re:       regexp.MustCompile(`sshd\[\d+\]:\s+(?:error: )?maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)`),
		typ:      event.TypeSSHLoginFailed,
		severity: event.SevMedium,
		title:    "SSH max auth attempts exceeded",
	},
}

// Detector tails an auth-log source and emits SSH events.
// Source can be a file path; "-" reads stdin.
type Detector struct {
	Source string
}

func (d *Detector) Name() string { return Name }

func (d *Detector) Run(ctx context.Context, out chan<- *event.Event) error {
	if d.Source == "-" {
		return d.runStdin(ctx, out)
	}
	return d.runFile(ctx, out)
}

func (d *Detector) runStdin(ctx context.Context, out chan<- *event.Event) error {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if e := match(scanner.Text()); e != nil {
			out <- e
		}
	}
	return scanner.Err()
}

func (d *Detector) runFile(ctx context.Context, out chan<- *event.Event) error {
	if d.Source == "" {
		return fmt.Errorf("ssh: no source configured")
	}
	// Fail loudly on missing source so the orchestrator emits agent.error.
	// Without this the user sees no events and can't tell if the detector
	// is broken or just nothing's happening.
	if _, err := os.Stat(d.Source); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("ssh: auth log %q does not exist (RHEL/CentOS uses /var/log/secure)", d.Source)
		}
		return fmt.Errorf("ssh: cannot stat %q: %w", d.Source, err)
	}
	t, err := tail.TailFile(d.Source, tail.Config{
		ReOpen:    true,
		Follow:    true,
		MustExist: false,
		Poll:      false,
		Logger:    tail.DiscardingLogger,
	})
	if err != nil {
		return fmt.Errorf("ssh: tail %s: %w", d.Source, err)
	}
	defer t.Cleanup()
	go func() {
		<-ctx.Done()
		_ = t.Stop()
	}()
	for line := range t.Lines {
		if line.Err != nil {
			continue
		}
		if e := match(line.Text); e != nil {
			out <- e
		}
	}
	return nil
}

func match(line string) *event.Event {
	for _, p := range patterns {
		m := p.re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ev := event.New(p.typ, p.severity, p.title).WithSource(Name)
		for i, name := range p.re.SubexpNames() {
			if name != "" && i < len(m) {
				ev.WithField(name, m[i])
			}
		}
		if p.method != "" {
			ev.WithField("method", p.method)
		}
		return ev
	}
	return nil
}
