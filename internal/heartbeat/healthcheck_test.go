package heartbeat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPinger_NoURLIsNoOp(t *testing.T) {
	p := &Pinger{}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not exit after cancel with empty URL")
	}
}

func TestPinger_PeriodicPings(t *testing.T) {
	var (
		mu      sync.Mutex
		hits    []string
		failHit int32
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.URL.Path)
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/fail") {
			atomic.StoreInt32(&failHit, 1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &Pinger{URL: srv.URL + "/abc-123", Interval: 80 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()

	// Allow ~3 ticks plus the initial ping.
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done

	mu.Lock()
	count := len(hits)
	mu.Unlock()

	if count < 3 {
		t.Errorf("expected >=3 pings, got %d", count)
	}
	if atomic.LoadInt32(&failHit) != 1 {
		t.Error("expected /fail ping on shutdown")
	}
}

func TestPinger_NetworkErrorDoesNotCrash(t *testing.T) {
	// Point at a closed port — pings will fail but the loop must keep going.
	p := &Pinger{
		URL:      "http://127.0.0.1:1/abc",
		Interval: 50 * time.Millisecond,
		HTTP:     &http.Client{Timeout: 100 * time.Millisecond},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Pinger did not survive network errors")
	}
}
