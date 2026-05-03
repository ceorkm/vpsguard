package audit

import (
	"testing"

	"github.com/ceorkm/vpsguard/internal/event"
)

func TestParseKernelModule(t *testing.T) {
	ev := parseLine(`type=SYSCALL msg=audit(1): syscall=finit_module exe="/usr/bin/insmod"`)
	if ev == nil || ev.Type != event.TypeAuditKernelModule {
		t.Fatalf("unexpected event: %+v", ev)
	}
}

func TestParseSensitiveFile(t *testing.T) {
	ev := parseLine(`type=PATH msg=audit(1): name="/etc/shadow" exe="/usr/bin/cat"`)
	if ev == nil || ev.Type != event.TypeAuditSensitiveFile {
		t.Fatalf("unexpected event: %+v", ev)
	}
}
