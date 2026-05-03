// Package cpu emits a cpu.spike event when host CPU stays above a high
// threshold for a sustained window. Reads /proc/stat on Linux; no-op on
// other platforms.
package cpu

import (
	"context"

	"github.com/ceorkm/vpsguard/internal/event"
)

const Name = "cpu"

type Detector struct {
	// Threshold is percent (0–100). Default 90.
	Threshold float64
	// SustainSeconds is how long CPU must stay above threshold. Default 300 (5 min).
	SustainSeconds int
}

func (d *Detector) Name() string { return Name }

func (d *Detector) Run(ctx context.Context, out chan<- *event.Event) error {
	if d.Threshold <= 0 {
		d.Threshold = 90
	}
	if d.SustainSeconds <= 0 {
		d.SustainSeconds = 300
	}
	return run(ctx, out, d.Threshold, d.SustainSeconds)
}
