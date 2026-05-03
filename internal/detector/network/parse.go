// Package network detects outbound connection abuse: a sudden surge of
// outbound TCP connections to many distinct destinations on attack-related
// ports (SSH 22, SMTP 25/465/587). This is the detector that would have
// caught the founder's incident — the VPS being used to brute-force other
// servers — without waiting for an external abuse report.
package network

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// procTCPConn is one parsed row from /proc/net/tcp or /proc/net/tcp6.
// We only care about ESTABLISHED outbound connections.
type procTCPConn struct {
	LocalAddr  netip.Addr
	LocalPort  uint16
	RemoteAddr netip.Addr
	RemotePort uint16
	State      uint8 // TCP state code per kernel: 01=ESTABLISHED, 02=SYN_SENT, ...
}

// TCP state constants from include/net/tcp_states.h.
const (
	stateEstablished = 0x01
	stateSynSent     = 0x02
)

var minerPorts = map[uint16]bool{
	3333:  true,
	4444:  true,
	5555:  true,
	7777:  true,
	14444: true,
}

// ParseProcNetTCP reads a /proc/net/tcp or /proc/net/tcp6 stream and
// returns rows. Header line is skipped. Malformed lines are skipped
// silently — these files are read every 30s, occasional partial-write
// races are normal.
//
// Format reference (Linux kernel net/ipv4/tcp_ipv4.c::tcp4_seq_show):
//
//	sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
//	 0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 ...
func ParseProcNetTCP(r io.Reader) []procTCPConn {
	var out []procTCPConn
	s := bufio.NewScanner(r)
	first := true
	for s.Scan() {
		if first {
			first = false // header
			continue
		}
		conn, ok := parseTCPLine(s.Text())
		if ok {
			out = append(out, conn)
		}
	}
	return out
}

func parseTCPLine(line string) (procTCPConn, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return procTCPConn{}, false
	}
	// fields[1] = local "ADDR:PORT", fields[2] = remote "ADDR:PORT", fields[3] = state hex.
	local, lok := parseAddrPort(fields[1])
	remote, rok := parseAddrPort(fields[2])
	if !lok || !rok {
		return procTCPConn{}, false
	}
	st, err := strconv.ParseUint(fields[3], 16, 8)
	if err != nil {
		return procTCPConn{}, false
	}
	return procTCPConn{
		LocalAddr:  local.addr,
		LocalPort:  local.port,
		RemoteAddr: remote.addr,
		RemotePort: remote.port,
		State:      uint8(st),
	}, true
}

type addrPort struct {
	addr netip.Addr
	port uint16
}

// parseAddrPort handles both "0100007F:0050" (IPv4 little-endian hex) and
// "00000000000000000000000001000000:0050" (IPv6 byte-swapped hex).
func parseAddrPort(s string) (addrPort, bool) {
	colon := strings.IndexByte(s, ':')
	if colon <= 0 {
		return addrPort{}, false
	}
	addrHex, portHex := s[:colon], s[colon+1:]
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return addrPort{}, false
	}
	switch len(addrHex) {
	case 8:
		// IPv4 — 4 bytes, little-endian, hex.
		b, err := hex.DecodeString(addrHex)
		if err != nil {
			return addrPort{}, false
		}
		ip := netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]})
		return addrPort{addr: ip, port: uint16(port)}, true
	case 32:
		// IPv6 — 16 bytes, but every 4-byte group is byte-swapped.
		b, err := hex.DecodeString(addrHex)
		if err != nil {
			return addrPort{}, false
		}
		var bytes [16]byte
		for i := 0; i < 16; i += 4 {
			bytes[i] = b[i+3]
			bytes[i+1] = b[i+2]
			bytes[i+2] = b[i+1]
			bytes[i+3] = b[i]
		}
		ip := netip.AddrFrom16(bytes)
		return addrPort{addr: ip.Unmap(), port: uint16(port)}, true
	}
	return addrPort{}, false
}

// IsLocalDest returns true for destinations we should not count as
// "outbound abuse" candidates: loopback, link-local, multicast, broadcast,
// and RFC1918 private ranges. These are all legitimate intra-VPS or
// LAN traffic from the agent's perspective.
func IsLocalDest(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	if addr.Is4() {
		b := addr.As4()
		// 10.0.0.0/8
		if b[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if b[0] == 172 && b[1] >= 16 && b[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if b[0] == 192 && b[1] == 168 {
			return true
		}
		// 169.254.0.0/16 — link-local (already by IsLinkLocalUnicast, but be explicit)
		if b[0] == 169 && b[1] == 254 {
			return true
		}
		// 100.64.0.0/10 — CGNAT
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 {
			return true
		}
		// 127.0.0.0/8 — covered by IsLoopback for the typical 127.0.0.1 but
		// not for anything else in the range.
		if b[0] == 127 {
			return true
		}
	}
	if addr.Is6() {
		// fc00::/7 — unique local addresses
		b := addr.As16()
		if b[0]&0xfe == 0xfc {
			return true
		}
	}
	return false
}

func IsAttackState(state uint8) bool {
	return state == stateEstablished || state == stateSynSent
}

func IsMinerPort(port uint16) bool {
	return minerPorts[port]
}

func IsCloudMetadataAddr(addr netip.Addr) bool {
	return addr.String() == "169.254.169.254" || addr.String() == "fd00:ec2::254"
}

func MatchKnownBadIP(addr netip.Addr, prefixes []netip.Prefix) bool {
	if !addr.IsValid() {
		return false
	}
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func deltaTX(prev, cur map[string]uint64) uint64 {
	var total uint64
	for iface, now := range cur {
		if old, ok := prev[iface]; ok && now >= old {
			total += now - old
		}
	}
	return total
}

var _ = fmt.Sprintf
