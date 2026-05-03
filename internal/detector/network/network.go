package network

import (
	"context"
	"net/netip"

	"github.com/ceorkm/vpsguard/internal/event"
)

const Name = "network"

// Detector polls /proc/net/tcp{,6} on Linux. Stub on other platforms.
type Detector struct {
	// Optional thresholds — zero means use defaults.
	SSHUniqueDsts  int // default 50
	SMTPUniqueDsts int // default 50
	RDPUniqueDsts  int // default 20
	KnownBadIPs    []netip.Prefix
}

func (d *Detector) Name() string { return Name }

func (d *Detector) Run(ctx context.Context, out chan<- *event.Event) error {
	return run(ctx, out, d)
}
