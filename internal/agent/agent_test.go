package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ceorkm/vpsguard/internal/detector"
	"github.com/ceorkm/vpsguard/internal/event"
)

// blockingDetector waits on ctx.Done. The healthy case.
type blockingDetector struct{ name string }

func (b *blockingDetector) Name() string { return b.name }
func (b *blockingDetector) Run(ctx context.Context, _ chan<- *event.Event) error {
	<-ctx.Done()
	return nil
}

// emittingDetector emits one event then waits.
type emittingDetector struct {
	name    string
	emitted *sync.WaitGroup
}

func (e *emittingDetector) Name() string { return e.name }
func (e *emittingDetector) Run(ctx context.Context, out chan<- *event.Event) error {
	out <- event.New(event.TypeAgentHeartbeat, event.SevInfo, "tick").WithSource(e.name)
	e.emitted.Done()
	<-ctx.Done()
	return nil
}

// failingDetector returns an error immediately. Should produce agent.error.
type failingDetector struct{ name string }

func (f *failingDetector) Name() string { return f.name }
func (f *failingDetector) Run(_ context.Context, _ chan<- *event.Event) error {
	return errors.New("simulated failure")
}

// earlyExitDetector returns nil before ctx is done. Should produce agent.error.
type earlyExitDetector struct{ name string }

func (e *earlyExitDetector) Name() string { return e.name }
func (e *earlyExitDetector) Run(_ context.Context, _ chan<- *event.Event) error {
	return nil
}

// recordingSink captures everything for assertions.
type recordingSink struct {
	mu     sync.Mutex
	events []*event.Event
	err    error
}

func (r *recordingSink) Name() string { return "recording" }
func (r *recordingSink) Send(_ context.Context, e *event.Event) error {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
	return r.err
}
func (r *recordingSink) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}
func (r *recordingSink) Snapshot() []*event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*event.Event, len(r.events))
	copy(out, r.events)
	return out
}

// countingBackground tracks how many times its Run was invoked.
type countingBackground struct{ called atomic.Int32 }

func (c *countingBackground) Run(ctx context.Context) {
	c.called.Add(1)
	<-ctx.Done()
}

func TestRun_GracefulShutdown(t *testing.T) {
	before := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	emitted := &sync.WaitGroup{}
	emitted.Add(2)

	a := &Agent{
		Server: "test-server",
		Sinks:  []Sink{NewStdoutSink(&bytes.Buffer{})},
		Detectors: []detector.Detector{
			&blockingDetector{name: "block-a"},
			&blockingDetector{name: "block-b"},
			&emittingDetector{name: "emit-a", emitted: emitted},
			&emittingDetector{name: "emit-b", emitted: emitted},
		},
	}

	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	emitted.Wait()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not exit within 2s of context cancellation")
	}

	time.Sleep(50 * time.Millisecond)
	after := runtime.NumGoroutine()
	if after > before+2 {
		t.Errorf("possible goroutine leak: before=%d after=%d", before, after)
	}
}

func TestRun_DetectorErrorEmitsAgentError(t *testing.T) {
	rec := &recordingSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := &Agent{
		Server: "test",
		Sinks:  []Sink{rec},
		Detectors: []detector.Detector{
			&failingDetector{name: "broken"},
		},
	}

	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not exit after only-detector failed")
	}

	events := rec.Snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != event.TypeAgentError {
		t.Errorf("expected agent.error, got %q", events[0].Type)
	}
	if !strings.Contains(events[0].Message, "simulated failure") {
		t.Errorf("expected error message in event, got: %q", events[0].Message)
	}
}

func TestRun_DetectorEarlyExitEmitsAgentError(t *testing.T) {
	rec := &recordingSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := &Agent{
		Sinks: []Sink{rec},
		Detectors: []detector.Detector{
			&earlyExitDetector{name: "ghost"},
		},
	}

	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not exit")
	}

	events := rec.Snapshot()
	if len(events) != 1 || events[0].Type != event.TypeAgentError {
		t.Fatalf("expected one agent.error, got %+v", events)
	}
	if !strings.Contains(events[0].Title, "exited unexpectedly") {
		t.Errorf("expected 'exited unexpectedly' in title, got: %q", events[0].Title)
	}
}

func TestRun_NoSinks(t *testing.T) {
	a := &Agent{}
	if err := a.Run(context.Background()); err == nil {
		t.Fatal("expected error for no sinks")
	}
}

func TestRun_MultiSinkFanout(t *testing.T) {
	a := &Agent{
		Sinks: []Sink{&recordingSink{}, &recordingSink{}, &recordingSink{}},
		Detectors: []detector.Detector{
			&failingDetector{name: "x"}, // produces 1 agent.error event
		},
	}
	done := make(chan error, 1)
	go func() { done <- a.Run(context.Background()) }()
	<-done

	for i, s := range a.Sinks {
		if c := s.(*recordingSink).Count(); c != 1 {
			t.Errorf("sink %d: got %d events, want 1", i, c)
		}
	}
}

func TestRun_SinkErrorDoesNotKillAgent(t *testing.T) {
	good := &recordingSink{}
	bad := &recordingSink{err: errors.New("sink down")}

	a := &Agent{
		Sinks: []Sink{good, bad},
		Detectors: []detector.Detector{
			&failingDetector{name: "x"},
		},
	}
	done := make(chan error, 1)
	go func() { done <- a.Run(context.Background()) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit when one sink errored")
	}
	if good.Count() != 1 {
		t.Errorf("good sink got %d events, want 1", good.Count())
	}
}

func TestRun_AttachesServerLabel(t *testing.T) {
	rec := &recordingSink{}
	ctx, cancel := context.WithCancel(context.Background())
	emitted := &sync.WaitGroup{}
	emitted.Add(1)

	a := &Agent{
		Server: "labelled-server",
		Sinks:  []Sink{rec},
		Detectors: []detector.Detector{
			&emittingDetector{name: "e", emitted: emitted},
		},
	}

	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	emitted.Wait()
	cancel()
	<-done

	events := rec.Snapshot()
	if len(events) == 0 {
		t.Fatal("no events received")
	}
	if events[0].Server != "labelled-server" {
		t.Errorf("expected server label, got %q", events[0].Server)
	}
}

func TestRun_BackgroundRunnersInvoked(t *testing.T) {
	bg := &countingBackground{}
	a := &Agent{
		Sinks: []Sink{&recordingSink{}},
		Detectors: []detector.Detector{
			&blockingDetector{name: "b"},
		},
		Background: []BackgroundRunner{bg, bg},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	if bg.called.Load() != 2 {
		t.Errorf("background runner called %d times, want 2", bg.called.Load())
	}
}

// doublingCorrelator emits the original event PLUS a derived heartbeat
// event for every input. Used to verify correlator wiring.
type doublingCorrelator struct{}

func (d *doublingCorrelator) Process(e *event.Event) []*event.Event {
	return []*event.Event{e, event.New(event.TypeAgentHeartbeat, event.SevInfo, "derived")}
}

func TestRun_CorrelatorRunsBeforeSinks(t *testing.T) {
	rec := &recordingSink{}
	a := &Agent{
		Sinks:      []Sink{rec},
		Correlator: &doublingCorrelator{},
		Detectors: []detector.Detector{
			&failingDetector{name: "x"}, // emits 1 agent.error
		},
	}
	done := make(chan error, 1)
	go func() { done <- a.Run(context.Background()) }()
	<-done

	if rec.Count() != 2 {
		t.Errorf("expected 2 events (original + derived), got %d", rec.Count())
	}
}

var _ = fmt.Sprintf
