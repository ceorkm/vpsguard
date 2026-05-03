// Package audit tails Linux audit.log and emits high-signal privilege,
// kernel-module, and sensitive-file access events.
package audit

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/ceorkm/vpsguard/internal/event"
	"github.com/nxadm/tail"
)

const Name = "audit"

type Detector struct {
	Path string
}

var (
	reExe  = regexp.MustCompile(`exe="([^"]+)"`)
	reName = regexp.MustCompile(`name="([^"]+)"`)
)

func (d *Detector) Name() string { return Name }

func (d *Detector) Run(ctx context.Context, out chan<- *event.Event) error {
	path := d.Path
	if path == "" {
		path = "/var/log/audit/audit.log"
	}
	if _, err := os.Stat(path); err != nil {
		<-ctx.Done()
		return nil
	}
	t, err := tail.TailFile(path, tail.Config{
		ReOpen: true, Follow: true, MustExist: true, Logger: tail.DiscardingLogger,
	})
	if err != nil {
		return fmt.Errorf("audit: tail %s: %w", path, err)
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
		if ev := parseLine(line.Text); ev != nil {
			out <- ev
		}
	}
	return nil
}

func parseLine(line string) *event.Event {
	low := strings.ToLower(line)
	switch {
	case strings.Contains(low, "syscall=") && (strings.Contains(low, "chmod") || strings.Contains(low, "fchmod") || strings.Contains(low, "key=setuid") || strings.Contains(low, "mode=4")):
		return event.New(event.TypeAuditSetuid, event.SevHigh, "Possible setuid permission change").
			WithSource(Name).
			WithField("exe", extract(reExe, line)).
			WithField("raw", line)
	case strings.Contains(low, "init_module") || strings.Contains(low, "finit_module") || strings.Contains(low, "delete_module") || strings.Contains(low, "key=kernel-module"):
		return event.New(event.TypeAuditKernelModule, event.SevCritical, "Kernel module activity detected").
			WithSource(Name).
			WithField("exe", extract(reExe, line)).
			WithField("raw", line)
	case strings.Contains(low, "/etc/shadow") || strings.Contains(low, "/.ssh/id_") || strings.Contains(low, "/.aws/credentials") || strings.Contains(low, "/.docker/config.json"):
		return event.New(event.TypeAuditSensitiveFile, event.SevHigh, "Sensitive file access detected").
			WithSource(Name).
			WithField("path", extract(reName, line)).
			WithField("exe", extract(reExe, line)).
			WithField("raw", line)
	case strings.Contains(low, "key=vpsguard-pam") || strings.Contains(low, "/etc/pam.d") || strings.Contains(low, "/lib/security"):
		return event.New(event.TypeSystemdServiceAdded, event.SevCritical, "PAM persistence path changed").
			WithSource(Name).
			WithMessage("PAM configuration or module paths changed; attackers use PAM backdoors for covert access and credential capture").
			WithField("path", extract(reName, line)).
			WithField("exe", extract(reExe, line)).
			WithField("raw", line).
			WithField("reason", "pam_modified")
	case strings.Contains(low, "key=vpsguard-docker-sock") || strings.Contains(low, "/var/run/docker.sock"):
		return event.New(event.TypeAuditSensitiveFile, event.SevHigh, "Docker socket access detected").
			WithSource(Name).
			WithMessage("Docker socket access can grant host-level control and is heavily abused in cloud miner campaigns").
			WithField("path", extract(reName, line)).
			WithField("exe", extract(reExe, line)).
			WithField("raw", line).
			WithField("reason", "docker_socket_access")
	case strings.Contains(low, "ptrace") || strings.Contains(low, "key=vpsguard-ptrace"):
		return event.New(event.TypeAuditSensitiveFile, event.SevHigh, "Process memory inspection detected").
			WithSource(Name).
			WithField("exe", extract(reExe, line)).
			WithField("raw", line).
			WithField("reason", "ptrace")
	}
	return nil
}

func extract(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}
