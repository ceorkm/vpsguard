// Package exposure detects risky services bound to public interfaces.
package exposure

import (
	"context"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
)

const Name = "exposure"

type Detector struct {
	Interval time.Duration
}

func (d *Detector) Name() string { return Name }

func (d *Detector) Run(ctx context.Context, out chan<- *event.Event) error {
	return run(ctx, out, d)
}
