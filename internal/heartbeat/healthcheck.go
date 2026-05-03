package heartbeat

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// Pinger periodically GETs a healthchecks.io-style URL. If the URL is
// empty, Run is a no-op (waits for context cancellation).
//
// On agent shutdown, Pinger does its best to fire one final POST to
// `<URL>/fail` so the user gets an immediate alert that the agent went
// silent rather than waiting for the silence-timeout.
type Pinger struct {
	URL      string
	Interval time.Duration // default 60s
	HTTP     *http.Client
}

func (p *Pinger) Run(ctx context.Context) {
	if p.URL == "" {
		<-ctx.Done()
		return
	}
	if p.Interval <= 0 {
		p.Interval = 60 * time.Second
	}
	if p.HTTP == nil {
		p.HTTP = &http.Client{Timeout: 10 * time.Second}
	}

	// Initial ping so the watchdog timer at healthchecks.io starts
	// immediately rather than waiting up to Interval.
	p.ping(ctx, p.URL)

	t := time.NewTicker(p.Interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			// Best-effort shutdown notification. Use a fresh, short-lived
			// context — the parent ctx is already cancelled.
			shut, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			p.ping(shut, p.URL+"/fail")
			cancel()
			return
		case <-t.C:
			p.ping(ctx, p.URL)
		}
	}
}

func (p *Pinger) ping(ctx context.Context, url string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		log.Printf("healthcheck: build request: %v", err)
		return
	}
	resp, err := p.HTTP.Do(req)
	if err != nil {
		// Network errors are non-fatal — healthchecks.io will alert on
		// silence anyway. Log for diagnostics.
		log.Printf("healthcheck: ping %s: %v", url, err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 400 {
		log.Printf("healthcheck: %s -> %d", url, resp.StatusCode)
	}
}

var _ = fmt.Sprintf
