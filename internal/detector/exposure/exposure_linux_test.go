//go:build linux

package exposure

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseListenSockets(t *testing.T) {
	sample := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0947 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1
   1: 0100007F:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2
   2: 00000000:0050 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 3
`
	got := parseListenSockets(strings.NewReader(sample))
	if len(got) != 2 {
		t.Fatalf("got %d sockets, want 2", len(got))
	}
	if got[0].port != 2375 || got[0].addr.String() != "0.0.0.0" {
		t.Fatalf("unexpected first socket: %#v", got[0])
	}
	if got[1].port != 6379 || got[1].addr.String() != "127.0.0.1" {
		t.Fatalf("unexpected second socket: %#v", got[1])
	}
}

func TestPublicBind(t *testing.T) {
	cases := map[string]bool{
		"0.0.0.0":      true,
		"::":           true,
		"127.0.0.1":    false,
		"10.0.0.1":     false,
		"192.168.1.10": false,
		"100.64.0.1":   false,
		"203.0.113.10": true,
		"2606:4700::1": true,
		"fc00::1":      false,
	}
	for raw, want := range cases {
		addr, _ := netip.ParseAddr(raw)
		if got := publicBind(addr); got != want {
			t.Errorf("publicBind(%s) = %v, want %v", raw, got, want)
		}
	}
}
