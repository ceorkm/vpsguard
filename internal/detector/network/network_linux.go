//go:build linux

package network

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
)

const (
	pollInterval = 30 * time.Second
	window       = 10 * time.Minute
)

var (
	smtpPorts = map[uint16]bool{25: true, 465: true, 587: true}
	sshPort   = uint16(22)
	rdpPort   = uint16(3389)
)

// observation is one outbound connection seen at a particular moment.
type observation struct {
	dst  netip.Addr
	port uint16
	when time.Time
}

func run(ctx context.Context, out chan<- *event.Event, d *Detector) error {
	sshThresh := d.SSHUniqueDsts
	if sshThresh <= 0 {
		sshThresh = 50
	}
	smtpThresh := d.SMTPUniqueDsts
	if smtpThresh <= 0 {
		smtpThresh = 50
	}
	rdpThresh := d.RDPUniqueDsts
	if rdpThresh <= 0 {
		rdpThresh = 20
	}

	hist := newHistory()
	devPrev := readNetDevTX()
	devPrevAt := time.Now()
	var alerted struct {
		mu                                sync.Mutex
		ssh, smtp, rdp, miner, bulk       time.Time
		knownBadConnection, cloudMetadata map[string]time.Time
	}
	alerted.knownBadConnection = map[string]time.Time{}
	alerted.cloudMetadata = map[string]time.Time{}

	t := time.NewTicker(pollInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			tick(hist, sshThresh, smtpThresh, rdpThresh, d.KnownBadIPs, &alerted, out)
			devNow := readNetDevTX()
			now := time.Now()
			if bytes := deltaTX(devPrev, devNow); bytes > 1024*1024*1024 && now.Sub(alerted.bulk) > window {
				alerted.bulk = now
				out <- event.New(event.TypeOutboundBulkTransfer, event.SevHigh, "High outbound transfer volume").
					WithSource(Name).
					WithMessage("network interfaces transmitted over 1 GiB since the last sample").
					WithField("bytes_sent", bytes).
					WithField("sample_seconds", int(now.Sub(devPrevAt).Seconds()))
			}
			devPrev = devNow
			devPrevAt = now
		}
	}
}

func tick(hist *history, sshThresh, smtpThresh, rdpThresh int, knownBad []netip.Prefix, alerted *struct {
	mu                                sync.Mutex
	ssh, smtp, rdp, miner, bulk       time.Time
	knownBadConnection, cloudMetadata map[string]time.Time
}, out chan<- *event.Event) {
	now := time.Now()

	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		conns := ParseProcNetTCP(f)
		_ = f.Close()
		for _, c := range conns {
			if !IsAttackState(c.State) {
				continue
			}
			if IsLocalDest(c.RemoteAddr) {
				if IsCloudMetadataAddr(c.RemoteAddr) {
					key := c.RemoteAddr.String()
					alerted.mu.Lock()
					last := alerted.cloudMetadata[key]
					canSend := now.Sub(last) > window
					if canSend {
						alerted.cloudMetadata[key] = now
					}
					alerted.mu.Unlock()
					if canSend {
						out <- event.New(event.TypeCloudMetadataAccess, event.SevHigh,
							"Cloud metadata service accessed").
							WithSource(Name).
							WithMessage("processes contacting cloud metadata can expose instance credentials after web compromise").
							WithField("ip", c.RemoteAddr.String()).
							WithField("port", c.RemotePort)
					}
				}
				continue
			}
			if MatchKnownBadIP(c.RemoteAddr, knownBad) {
				key := c.RemoteAddr.String()
				alerted.mu.Lock()
				last := alerted.knownBadConnection[key]
				canSend := now.Sub(last) > window
				if canSend {
					alerted.knownBadConnection[key] = now
				}
				alerted.mu.Unlock()
				if canSend {
					out <- event.New(event.TypeKnownBadConnection, event.SevCritical,
						"Outbound connection to known-bad IP").
						WithSource(Name).
						WithMessage("this VPS contacted an IP/CIDR listed in known_bad_ips").
						WithField("ip", c.RemoteAddr.String()).
						WithField("port", c.RemotePort)
				}
			}
			hist.add(c.RemoteAddr, c.RemotePort, now)
		}
	}

	hist.prune(now.Add(-window))

	// SSH spike: too many unique dst IPs to port 22.
	if uniq := hist.uniqueDstsForPort(sshPort); uniq >= sshThresh {
		alerted.mu.Lock()
		canSend := now.Sub(alerted.ssh) > window
		if canSend {
			alerted.ssh = now
		}
		alerted.mu.Unlock()
		if canSend {
			out <- event.New(event.TypeOutboundSSHSpike, event.SevHigh,
				"Possible outbound SSH brute-force from this server").
				WithSource(Name).
				WithMessage(fmt.Sprintf("connections to %d unique remote IPs on port 22 within %s — your VPS may be attacking other machines", uniq, window)).
				WithField("unique_dst_ips", uniq).
				WithField("port", sshPort).
				WithField("window", window.String())
		}
	}

	// SMTP spike: too many unique dst IPs to common SMTP ports combined.
	smtpUniq := 0
	for p := range smtpPorts {
		smtpUniq += hist.uniqueDstsForPort(p)
	}
	if smtpUniq >= smtpThresh {
		alerted.mu.Lock()
		canSend := now.Sub(alerted.smtp) > window
		if canSend {
			alerted.smtp = now
		}
		alerted.mu.Unlock()
		if canSend {
			out <- event.New(event.TypeOutboundSMTPSpike, event.SevHigh,
				"Possible outbound spam / SMTP abuse").
				WithSource(Name).
				WithMessage(fmt.Sprintf("connections to %d unique remote SMTP servers within %s — your VPS may be relaying spam", smtpUniq, window)).
				WithField("unique_dst_ips", smtpUniq).
				WithField("ports", "25, 465, 587").
				WithField("window", window.String())
		}
	}

	// RDP spike: a compromised Linux VPS can be used to spray Windows hosts.
	if uniq := hist.uniqueDstsForPort(rdpPort); uniq >= rdpThresh {
		alerted.mu.Lock()
		canSend := now.Sub(alerted.rdp) > window
		if canSend {
			alerted.rdp = now
		}
		alerted.mu.Unlock()
		if canSend {
			out <- event.New(event.TypeOutboundRDPSpike, event.SevHigh,
				"Possible outbound RDP brute-force from this server").
				WithSource(Name).
				WithMessage(fmt.Sprintf("connections to %d unique remote IPs on port 3389 within %s — your VPS may be attacking Windows hosts", uniq, window)).
				WithField("unique_dst_ips", uniq).
				WithField("port", rdpPort).
				WithField("window", window.String())
		}
	}

	// Mining pools commonly listen on these stratum ports. One connection is
	// already suspicious on a VPS when paired with process/CPU alerts, so we
	// emit a high-signal network clue immediately and suppress repeats.
	minerUniq := 0
	for p := range minerPorts {
		minerUniq += hist.uniqueDstsForPort(p)
	}
	if minerUniq > 0 {
		alerted.mu.Lock()
		canSend := now.Sub(alerted.miner) > window
		if canSend {
			alerted.miner = now
		}
		alerted.mu.Unlock()
		if canSend {
			out <- event.New(event.TypeOutboundMinerPool, event.SevHigh,
				"Possible crypto-miner pool connection").
				WithSource(Name).
				WithMessage("outbound connection to a common mining-pool port — investigate alongside process and CPU alerts").
				WithField("unique_dst_ips", minerUniq).
				WithField("ports", "3333, 4444, 5555, 7777, 14444").
				WithField("window", window.String())
		}
	}
}

// history is a sliding window of (dst,port,time) observations, indexed
// by port for O(1) per-port unique counts.
type history struct {
	mu     sync.Mutex
	byPort map[uint16][]observation
}

func newHistory() *history {
	return &history{byPort: map[uint16][]observation{}}
}

func (h *history) add(dst netip.Addr, port uint16, when time.Time) {
	if _, watched := smtpPorts[port]; !watched && port != sshPort && port != rdpPort && !IsMinerPort(port) {
		return // we only track ports we alert on
	}
	h.mu.Lock()
	h.byPort[port] = append(h.byPort[port], observation{dst: dst, port: port, when: when})
	h.mu.Unlock()
}

func (h *history) prune(cutoff time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for port, obs := range h.byPort {
		out := obs[:0]
		for _, o := range obs {
			if !o.when.Before(cutoff) {
				out = append(out, o)
			}
		}
		h.byPort[port] = out
	}
}

func (h *history) uniqueDstsForPort(port uint16) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	seen := map[netip.Addr]struct{}{}
	for _, o := range h.byPort[port] {
		seen[o.dst] = struct{}{}
	}
	return len(seen)
}

func readNetDevTX() map[string]uint64 {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]uint64{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		iface := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) < 16 || iface == "lo" {
			continue
		}
		tx, err := strconv.ParseUint(fields[8], 10, 64)
		if err == nil {
			out[iface] = tx
		}
	}
	return out
}
