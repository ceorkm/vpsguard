// Package heartbeat emits a periodic agent.heartbeat event so that
// downstream sinks (and, in v0.2+, healthchecks.io) can detect agent
// silence — the canonical tamper-detection signal.
package heartbeat

import (
	"context"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
)

const Name = "heartbeat"

type Detector struct {
	Interval time.Duration // default 30s
}

func (d *Detector) Name() string { return Name }

func (d *Detector) Run(ctx context.Context, out chan<- *event.Event) error {
	if d.Interval <= 0 {
		d.Interval = 30 * time.Second
	}

	out <- event.New(event.TypeAgentStarted, event.SevInfo, "vpsguard agent started").
		WithSource(Name)

	t := time.NewTicker(d.Interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			out <- event.New(event.TypeAgentStopped, event.SevInfo, "vpsguard agent stopping").
				WithSource(Name)
			return nil
		case <-t.C:
			out <- event.New(event.TypeAgentHeartbeat, event.SevInfo, "agent heartbeat").
				WithSource(Name).
				WithField("interval_seconds", int(d.Interval.Seconds()))
		}
	}
}
