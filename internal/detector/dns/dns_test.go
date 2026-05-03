package dns

import (
	"testing"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
)

func TestExtractDomain(t *testing.T) {
	line := `May 03 dnsmasq[100]: query[A] aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.example from 10.0.0.2`
	got := ExtractDomain(line)
	want := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.example"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSuspiciousDomain(t *testing.T) {
	if SuspiciousDomain("short.example.com") != "" {
		t.Fatal("short domain should not be suspicious")
	}
	if got := SuspiciousDomain("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com"); got != "long_label" {
		t.Fatalf("got %q, want long_label", got)
	}
	if got := SuspiciousDomain("abc123def456ghi789jkl012mno345pq.example.com"); got != "encoded_subdomain" {
		t.Fatalf("got %q, want encoded_subdomain", got)
	}
}

func TestMatchKnownBadDomain(t *testing.T) {
	known := []string{"evil.example"}
	if got := MatchKnownBadDomain("payload.evil.example", known); got != "evil.example" {
		t.Fatalf("subdomain match got %q", got)
	}
	if got := MatchKnownBadDomain("notevil.example.org", known); got != "" {
		t.Fatalf("unexpected match %q", got)
	}
}

func TestHandleLineEmitsKnownBadAndTunnel(t *testing.T) {
	out := make(chan *event.Event, 4)
	d := &Detector{
		KnownBadDomains: []string{"evil.example"},
		Threshold:       2,
		Window:          time.Minute,
	}
	seen := map[string]*domainState{}
	alerted := map[string]time.Time{}
	line := `dnsmasq[100]: query[A] aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.example from 10.0.0.2`
	d.HandleLine(line, "test.log", seen, alerted, out)
	d.HandleLine(line, "test.log", seen, alerted, out)
	close(out)

	var gotKnown, gotTunnel bool
	for ev := range out {
		if ev.Type == event.TypeKnownBadDomain {
			gotKnown = true
		}
		if ev.Type == event.TypeDNSAnomaly {
			gotTunnel = true
		}
	}
	if !gotKnown {
		t.Fatal("known-bad domain event not emitted")
	}
	if !gotTunnel {
		t.Fatal("DNS tunneling event not emitted")
	}
}
