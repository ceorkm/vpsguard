//go:build linux

package exposure

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
)

const defaultInterval = 5 * time.Minute

type listenSocket struct {
	addr netip.Addr
	port uint16
}

type riskyService struct {
	name     string
	severity event.Severity
	reason   string
}

var riskyPorts = map[uint16]riskyService{
	2375:  {"Docker API", event.SevCritical, "unauthenticated Docker APIs are routinely abused to mount the host filesystem and drop miners or bot tooling"},
	2376:  {"Docker API TLS", event.SevHigh, "Docker API should not be internet-facing unless tightly authenticated and firewalled"},
	4243:  {"Docker API", event.SevCritical, "legacy Docker API exposure is a common cloud compromise path"},
	6379:  {"Redis", event.SevCritical, "internet-facing Redis is commonly abused for cron/SSH-key persistence and cryptomining"},
	5432:  {"PostgreSQL", event.SevHigh, "public PostgreSQL with weak credentials is a current cryptomining initial-access path"},
	3306:  {"MySQL/MariaDB", event.SevHigh, "public database ports invite brute-force and exploit attempts"},
	27017: {"MongoDB", event.SevHigh, "public MongoDB is commonly targeted for theft, extortion, and malware staging"},
	9200:  {"Elasticsearch", event.SevHigh, "public Elasticsearch has a long history of unauthenticated data exposure and RCE chains"},
	9300:  {"Elasticsearch transport", event.SevHigh, "Elasticsearch transport should not be public on a VPS"},
	7001:  {"Oracle WebLogic", event.SevHigh, "public WebLogic is frequently scanned for RCE and Linux miner deployment"},
	7002:  {"Oracle WebLogic", event.SevHigh, "public WebLogic is frequently scanned for RCE and Linux miner deployment"},
	8080:  {"HTTP admin/dev service", event.SevMedium, "public admin/dev services such as Jenkins, Tomcat, and panels are frequent footholds"},
	8081:  {"HTTP admin/dev service", event.SevMedium, "public admin/dev services should be reviewed and restricted"},
	8888:  {"Jupyter/dev notebook", event.SevHigh, "public notebook servers can execute arbitrary code if misconfigured"},
	5000:  {"Docker registry/dev app", event.SevMedium, "public dev services and registries should be intentional and authenticated"},
	5900:  {"VNC", event.SevHigh, "public VNC is commonly brute-forced"},
	5901:  {"VNC", event.SevHigh, "public VNC is commonly brute-forced"},
	6443:  {"Kubernetes API", event.SevCritical, "public Kubernetes API exposure can lead to full cluster compromise"},
	10250: {"Kubelet API", event.SevCritical, "public kubelet APIs are a known container compromise path"},
	11211: {"Memcached", event.SevHigh, "public memcached is abused for data exposure and DDoS amplification"},
}

func run(ctx context.Context, out chan<- *event.Event, d *Detector) error {
	interval := d.Interval
	if interval <= 0 {
		interval = defaultInterval
	}
	alerted := map[string]time.Time{}
	scan(alerted, out)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			scan(alerted, out)
		}
	}
}

func scan(alerted map[string]time.Time, out chan<- *event.Event) {
	now := time.Now()
	for _, sock := range listenSockets() {
		meta, ok := riskyPorts[sock.port]
		if !ok || !publicBind(sock.addr) {
			continue
		}
		key := fmt.Sprintf("%s:%d", sock.addr, sock.port)
		if now.Sub(alerted[key]) < 24*time.Hour {
			continue
		}
		alerted[key] = now
		out <- event.New(event.TypeServiceExposed, meta.severity, "Risky service exposed publicly").
			WithSource(Name).
			WithMessage(meta.reason).
			WithField("service", meta.name).
			WithField("ip", sock.addr.String()).
			WithField("port", sock.port)
	}
}

func listenSockets() []listenSocket {
	var out []listenSocket
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		out = append(out, parseListenSockets(f)...)
		_ = f.Close()
	}
	return out
}

func parseListenSockets(r io.Reader) []listenSocket {
	var out []listenSocket
	s := bufio.NewScanner(r)
	first := true
	for s.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(s.Text())
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		addr, port, ok := parseLocal(fields[1])
		if ok {
			out = append(out, listenSocket{addr: addr, port: port})
		}
	}
	return out
}

func parseLocal(raw string) (netip.Addr, uint16, bool) {
	i := strings.IndexByte(raw, ':')
	if i <= 0 {
		return netip.Addr{}, 0, false
	}
	port, err := strconv.ParseUint(raw[i+1:], 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	addr, ok := decodeProcAddr(raw[:i])
	return addr, uint16(port), ok
}

func decodeProcAddr(h string) (netip.Addr, bool) {
	switch len(h) {
	case 8:
		b, err := hex.DecodeString(h)
		if err != nil {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]}), true
	case 32:
		b, err := hex.DecodeString(h)
		if err != nil {
			return netip.Addr{}, false
		}
		var arr [16]byte
		for i := 0; i < 16; i += 4 {
			arr[i] = b[i+3]
			arr[i+1] = b[i+2]
			arr[i+2] = b[i+1]
			arr[i+3] = b[i]
		}
		return netip.AddrFrom16(arr).Unmap(), true
	}
	return netip.Addr{}, false
}

func publicBind(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if addr.IsUnspecified() {
		return true
	}
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsPrivate() {
		return false
	}
	if addr.Is4() {
		b := addr.As4()
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 {
			return false
		}
	}
	if addr.Is6() {
		b := addr.As16()
		if b[0]&0xfe == 0xfc {
			return false
		}
	}
	return true
}
