// Package process scans /proc periodically for suspicious processes:
// executables in /tmp, /dev/shm, /var/tmp; cmdlines matching known
// crypto-miner names. Linux-only; stubs out cleanly on darwin so the
// project still builds for development on macOS.
package process

import (
	"context"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
)

const Name = "process"

// Detector scans /proc. Zero-value uses MVP defaults.
type Detector struct {
	HighCPUThreshold float64 // default 70 (% of one CPU core)
	HighCPUSustain   time.Duration
}

func (d *Detector) Name() string { return Name }

func (d *Detector) Run(ctx context.Context, out chan<- *event.Event) error {
	return run(ctx, out, d)
}
