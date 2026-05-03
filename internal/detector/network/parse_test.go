package network

import (
	"net/netip"
	"strings"
	"testing"
)

const sampleTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 ffff
   1: 0100007F:1F90 0100007F:E22A 01 00000000:00000000 00:00000000 00000000     0        0 67890 1 ffff
   2: 040A640A:E92E 8908080F:0016 01 00000000:00000000 00:00000000 00000000     0        0 11111 1 ffff
`

const sampleTCP6 = `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1
   1: 0000000000000000FFFF000001020304:F1B5 0000000000000000FFFF00000A0B0C0D:0016 01 00000000:00000000 00:00000000 00000000     0        0 2
`

func TestParseProcNetTCP_IPv4(t *testing.T) {
	conns := ParseProcNetTCP(strings.NewReader(sampleTCP))
	if len(conns) != 3 {
		t.Fatalf("got %d rows, want 3", len(conns))
	}

	// Row 1: 127.0.0.1:80 listen (state 0A = LISTEN)
	if conns[0].State != 0x0A {
		t.Errorf("row 0 state: %x", conns[0].State)
	}
	if conns[0].LocalAddr.String() != "127.0.0.1" {
		t.Errorf("row 0 local: %s", conns[0].LocalAddr)
	}
	if conns[0].LocalPort != 80 {
		t.Errorf("row 0 port: %d", conns[0].LocalPort)
	}

	// Row 2: 127.0.0.1:8080 -> 127.0.0.1:57898 ESTABLISHED
	if conns[1].State != stateEstablished {
		t.Errorf("row 1 state: %x", conns[1].State)
	}
	if conns[1].RemoteAddr.String() != "127.0.0.1" {
		t.Errorf("row 1 remote: %s", conns[1].RemoteAddr)
	}

	// Row 3: 10.100.10.4:59694 -> 15.8.8.137:22 ESTABLISHED (outbound SSH!)
	if conns[2].RemotePort != 22 {
		t.Errorf("row 2 remote port: %d", conns[2].RemotePort)
	}
	if conns[2].RemoteAddr.String() != "15.8.8.137" {
		t.Errorf("row 2 remote: %s", conns[2].RemoteAddr)
	}
	if conns[2].LocalAddr.String() != "10.100.10.4" {
		t.Errorf("row 2 local: %s", conns[2].LocalAddr)
	}
}

func TestParseProcNetTCP_IPv6(t *testing.T) {
	conns := ParseProcNetTCP(strings.NewReader(sampleTCP6))
	if len(conns) != 2 {
		t.Fatalf("got %d rows, want 2", len(conns))
	}
	// Row 1: fully zero ::; listen
	if conns[0].State != 0x0A {
		t.Errorf("v6 row 0 state: %x", conns[0].State)
	}
	// Row 2: ESTABLISHED, expect IPv4-mapped IPv6 unmapped to bare IPv4
	if conns[1].State != stateEstablished {
		t.Errorf("v6 row 1 state: %x", conns[1].State)
	}
	if conns[1].RemotePort != 22 {
		t.Errorf("v6 row 1 remote port: %d", conns[1].RemotePort)
	}
}

func TestParseProcNetTCP_SkipsHeader(t *testing.T) {
	in := "  sl  local_address rem_address st\n"
	conns := ParseProcNetTCP(strings.NewReader(in))
	if len(conns) != 0 {
		t.Errorf("header-only must produce 0 rows, got %d", len(conns))
	}
}

func TestParseProcNetTCP_SkipsMalformed(t *testing.T) {
	in := `  sl local rem st
   0: bogus
   1: 0100007F:0050 00000000:0000 0A
   2: not enough fields
`
	conns := ParseProcNetTCP(strings.NewReader(in))
	if len(conns) != 1 {
		t.Errorf("expected 1 valid row, got %d", len(conns))
	}
}

func TestIsAttackState(t *testing.T) {
	if !IsAttackState(stateEstablished) {
		t.Fatal("ESTABLISHED must be tracked")
	}
	if !IsAttackState(stateSynSent) {
		t.Fatal("SYN_SENT must be tracked so short brute-force attempts are not missed")
	}
	if IsAttackState(0x0A) {
		t.Fatal("LISTEN sockets must not be tracked as outbound abuse")
	}
}

func TestIsMinerPort(t *testing.T) {
	for _, port := range []uint16{3333, 4444, 5555, 7777, 14444} {
		if !IsMinerPort(port) {
			t.Fatalf("port %d should be treated as miner-pool traffic", port)
		}
	}
	if IsMinerPort(22) {
		t.Fatal("port 22 is SSH abuse, not miner-pool traffic")
	}
}

func TestIsCloudMetadataAddr(t *testing.T) {
	addr, _ := netip.ParseAddr("169.254.169.254")
	if !IsCloudMetadataAddr(addr) {
		t.Fatal("metadata IPv4 missed")
	}
	other, _ := netip.ParseAddr("169.254.1.1")
	if IsCloudMetadataAddr(other) {
		t.Fatal("generic link local should not be metadata")
	}
}

func TestMatchKnownBadIP(t *testing.T) {
	addr, _ := netip.ParseAddr("203.0.113.66")
	other, _ := netip.ParseAddr("203.0.114.1")
	prefix, _ := netip.ParsePrefix("203.0.113.0/24")
	if !MatchKnownBadIP(addr, []netip.Prefix{prefix}) {
		t.Fatal("known-bad CIDR did not match")
	}
	if MatchKnownBadIP(other, []netip.Prefix{prefix}) {
		t.Fatal("outside CIDR matched")
	}
}

func TestDeltaTX(t *testing.T) {
	got := deltaTX(map[string]uint64{"eth0": 10, "eth1": 5}, map[string]uint64{"eth0": 15, "eth1": 7})
	if got != 7 {
		t.Fatalf("got %d", got)
	}
}

func TestIsLocalDest(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.5.6.7", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.0.1", true},
		{"172.32.0.1", false}, // outside 12-bit range
		{"172.15.0.1", false}, // before range
		{"192.168.1.1", true},
		{"192.169.1.1", false},
		{"169.254.1.1", true},  // link-local
		{"100.64.0.1", true},   // CGNAT
		{"100.128.0.1", false}, // outside CGNAT
		{"0.0.0.0", true},      // unspecified
		{"8.8.8.8", false},     // public
		{"185.220.101.45", false},
		{"::1", true},
		{"fe80::1", true},       // link-local v6
		{"fc00::1", true},       // ULA
		{"2001:db8::1", false},  // public-ish (doc range)
		{"2606:4700::1", false}, // public
	}
	for _, c := range cases {
		addr, _ := netip.ParseAddr(c.ip)
		got := IsLocalDest(addr)
		if got != c.want {
			t.Errorf("IsLocalDest(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}
