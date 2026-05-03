package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/ceorkm/vpsguard/internal/detector"
	"github.com/ceorkm/vpsguard/internal/event"
)

// Correlator transforms events as they flow from detectors to sinks.
// Process receives one event and returns the original (possibly with
// fields/severity adjusted) plus zero or more derived events.
type Correlator interface {
	Process(e *event.Event) []*event.Event
}

type Agent struct {
	Server     string
	Detectors  []detector.Detector
	Sinks      []Sink
	Correlator Correlator

	// Background runs alongside the detectors but does not produce events
	// (e.g. healthchecks.io pinger).
	Background []BackgroundRunner
}

// BackgroundRunner is a goroutine that runs for the agent lifetime and
// produces no events of its own (e.g. heartbeat pinger).
type BackgroundRunner interface {
	Run(ctx context.Context)
}

// Run starts every detector + background runner concurrently and fans
// every event out to every sink.
func (a *Agent) Run(ctx context.Context) error {
	if len(a.Sinks) == 0 {
		return errors.New("agent: no sinks configured")
	}

	events := make(chan *event.Event, 256)

	var wg sync.WaitGroup
	for _, d := range a.Detectors {
		wg.Add(1)
		go func(d detector.Detector) {
			defer wg.Done()
			err := d.Run(ctx, events)
			if ctx.Err() != nil {
				return
			}
			a.emitDetectorExit(events, d.Name(), err)
		}(d)
	}

	for _, b := range a.Background {
		wg.Add(1)
		go func(b BackgroundRunner) {
			defer wg.Done()
			b.Run(ctx)
		}(b)
	}

	go func() {
		wg.Wait()
		close(events)
	}()

	for e := range events {
		if e == nil {
			continue
		}
		if a.Server != "" && e.Server == "" {
			e.Server = a.Server
		}
		// Run through the correlator (if any), then fan every produced
		// event out to all sinks.
		if a.Correlator != nil {
			for _, derived := range a.Correlator.Process(e) {
				if derived == nil {
					continue
				}
				if a.Server != "" && derived.Server == "" {
					derived.Server = a.Server
				}
				a.fanout(ctx, derived)
			}
		} else {
			a.fanout(ctx, e)
		}
	}
	return nil
}

// fanout sends e to every sink concurrently. A failing sink does not
// affect any other. Sink errors are already logged inside the sink.
func (a *Agent) fanout(ctx context.Context, e *event.Event) {
	if len(a.Sinks) == 1 {
		// Common case: stdout-only. No goroutine overhead.
		_ = a.Sinks[0].Send(ctx, e)
		return
	}
	var wg sync.WaitGroup
	for _, s := range a.Sinks {
		wg.Add(1)
		go func(s Sink) {
			defer wg.Done()
			if err := s.Send(ctx, e); err != nil {
				log.Printf("sink %q failed for event %q: %v", s.Name(), e.Type, err)
			}
		}(s)
	}
	wg.Wait()
}

func (a *Agent) emitDetectorExit(events chan<- *event.Event, name string, err error) {
	var ev *event.Event
	if err != nil {
		ev = event.New(event.TypeAgentError, event.SevHigh,
			fmt.Sprintf("detector %q failed", name)).
			WithSource(name).
			WithMessage(err.Error()).
			WithField("detector", name).
			WithField("error", err.Error())
	} else {
		ev = event.New(event.TypeAgentError, event.SevHigh,
			fmt.Sprintf("detector %q exited unexpectedly", name)).
			WithSource(name).
			WithMessage("detector returned without an error before shutdown was requested").
			WithField("detector", name)
	}
	defer func() { _ = recover() }() // events channel may be closed during shutdown race
	events <- ev
}
