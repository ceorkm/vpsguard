package process

import (
	"bufio"
	"encoding/hex"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// Sensitive paths that should never be open by an arbitrary process.
// A process holding any of these as an open file descriptor is treated
// as performing credential access — fires regardless of CPU, regardless
// of process name, regardless of source. Picks up stealers natively
// without any auditd / fanotify / eBPF dependency.
var sensitivePathPrefixes = []string{
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/ssh/ssh_host_",
	"/root/.ssh/id_",
	"/root/.aws/credentials",
	"/root/.aws/config",
	"/root/.config/gcloud/",
	"/root/.docker/config.json",
	"/root/.kube/config",
	"/root/.npmrc",
	"/root/.pypirc",
	"/root/.git-credentials",
	"/root/.config/gh/hosts.yml",
	"/root/.bash_history",
	"/root/.zsh_history",
	"/dev/input/",
	"/dev/uinput",
}

// Per-user home prefixes are checked separately because /home/<user>/
// is dynamic.
var sensitiveHomeSuffixes = []string{
	"/.ssh/id_rsa",
	"/.ssh/id_ed25519",
	"/.ssh/id_ecdsa",
	"/.ssh/id_dsa",
	"/.aws/credentials",
	"/.aws/config",
	"/.config/gcloud/credentials.db",
	"/.config/gcloud/legacy_credentials/",
	"/.docker/config.json",
	"/.kube/config",
	"/.npmrc",
	"/.pypirc",
	"/.git-credentials",
	"/.config/gh/hosts.yml",
	"/.bash_history",
	"/.zsh_history",
}

func isSensitivePath(p string) bool {
	for _, prefix := range sensitivePathPrefixes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	// SSH agent sockets — `/tmp/ssh-XXXX/agent.NNN` and
	// `/run/user/<uid>/keyring/ssh` and friends. A non-ssh-client process
	// holding the agent socket open is credential theft (the agent
	// proxies signing operations using your loaded keys).
	if strings.HasPrefix(p, "/tmp/ssh-") && strings.Contains(p, "/agent.") {
		return true
	}
	if strings.HasPrefix(p, "/run/user/") {
		// /run/user/<uid>/keyring/ssh OR /run/user/<uid>/gnupg/S.gpg-agent.ssh
		if strings.HasSuffix(p, "/keyring/ssh") ||
			strings.HasSuffix(p, "/keyring/.ssh") ||
			strings.Contains(p, "/gnupg/S.gpg-agent") {
			return true
		}
	}
	// Kubernetes pod-mounted serviceaccount tokens.
	if strings.HasPrefix(p, "/var/run/secrets/kubernetes.io/serviceaccount/") {
		return true
	}
	if strings.HasPrefix(p, "/home/") {
		rest := strings.TrimPrefix(p, "/home/")
		slash := strings.IndexByte(rest, '/')
		if slash < 0 {
			return false
		}
		userRel := rest[slash:]
		for _, suffix := range sensitiveHomeSuffixes {
			if strings.HasPrefix(userRel, suffix) {
				return true
			}
		}
	}
	return false
}

// scanTCPForPublicOutbound reads a /proc/PID/net/tcp{,6} stream and
// returns true on the first ESTABLISHED or SYN_SENT connection whose
// remote address is a routable, non-RFC1918, non-loopback IP.
func scanTCPForPublicOutbound(r io.Reader) bool {
	s := bufio.NewScanner(r)
	first := true
	for s.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(s.Text())
		if len(fields) < 4 {
			continue
		}
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil || (state != 0x01 && state != 0x02) {
			continue
		}
		remote := fields[2]
		colon := strings.IndexByte(remote, ':')
		if colon <= 0 {
			continue
		}
		addr, ok := decodeProcAddr(remote[:colon])
		if !ok {
			continue
		}
		if isPublicAddr(addr) {
			return true
		}
	}
	return false
}

// decodeProcAddr handles the kernel's hex-encoded little-endian IPv4
// (8 chars) and 4-byte-swapped IPv6 (32 chars) format used in
// /proc/net/tcp.
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

// isPublicAddr returns true for addresses we treat as "the internet" —
// not loopback, link-local, multicast, RFC1918, CGNAT, or ULA.
func isPublicAddr(addr netip.Addr) bool {
	if !addr.IsValid() ||
		addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	if addr.Is4() {
		b := addr.As4()
		switch {
		case b[0] == 10:
			return false
		case b[0] == 172 && b[1] >= 16 && b[1] <= 31:
			return false
		case b[0] == 192 && b[1] == 168:
			return false
		case b[0] == 169 && b[1] == 254:
			return false
		case b[0] == 100 && b[1] >= 64 && b[1] <= 127:
			return false
		case b[0] == 127:
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
