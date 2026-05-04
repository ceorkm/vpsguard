//go:build linux

package process

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// scanFDsForSensitive walks /proc/PID/fd and returns the first sensitive
// path the process has open, or "" if none. Cheap: a typical process
// has 5–30 open fds.
func scanFDsForSensitive(pid int, exe, cmdline string) string {
	fdDir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return "" // process gone or no permission — skip silently
	}
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		// Strip "(deleted)" suffix the kernel adds for unlinked-but-open files.
		target = strings.TrimSuffix(target, " (deleted)")

		if !strings.HasPrefix(target, "/") {
			continue // sockets, pipes, anon_inodes, etc.
		}
		if isBenignSensitiveFDReader(exe, cmdline, target) {
			continue
		}
		if isSensitivePath(target) {
			return target
		}
	}
	return ""
}

func isBenignSensitiveFDReader(exe, cmdline, target string) bool {
	if strings.HasPrefix(target, "/dev/input/") || target == "/dev/uinput" {
		switch filepath.Base(exe) {
		case "Xorg", "Xwayland", "systemd-logind", "lightdm", "gdm", "gdm-x-session", "sddm", "seatd":
			return true
		}
		if strings.Contains(cmdline, "/usr/lib/xorg/Xorg") ||
			strings.Contains(cmdline, "systemd-logind") {
			return true
		}
	}
	return false
}

// hasOutboundSocket returns true if the PID has at least one TCP
// connection in ESTABLISHED or SYN_SENT to a non-RFC1918, non-loopback
// destination. Reads /proc/PID/net/tcp + /proc/PID/net/tcp6 — these
// files show all sockets in the PID's network namespace.
//
// The check is deliberately blunt: we do not care WHERE the connection
// is going; the fact that a binary in /tmp dialed the public internet
// at all is enough. False-positive rate on a clean VPS is essentially
// zero — legit binaries do not live in /tmp.
func hasOutboundSocket(pid int) bool {
	for _, name := range []string{"net/tcp", "net/tcp6"} {
		path := filepath.Join("/proc", strconv.Itoa(pid), name)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		found := scanTCPForPublicOutbound(f)
		_ = f.Close()
		if found {
			return true
		}
	}
	return false
}
