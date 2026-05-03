// Package rootkit performs periodic userspace rootkit sanity checks.
package rootkit

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
)

const Name = "rootkit"

type Detector struct {
	Interval time.Duration
}

func (d *Detector) Name() string { return Name }

func (d *Detector) Run(ctx context.Context, out chan<- *event.Event) error {
	interval := d.Interval
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	scan(out)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			scan(out)
		}
	}
}

func scan(out chan<- *event.Event) {
	for _, ev := range checkDevRegularFiles() {
		out <- ev
	}
	for _, ev := range checkPromisc() {
		out <- ev
	}
	for _, ev := range checkHiddenPIDs() {
		out <- ev
	}
	for _, ev := range checkHiddenPorts() {
		out <- ev
	}
	for _, ev := range checkFileSizeMismatches() {
		out <- ev
	}
	for _, ev := range checkDirLinkCounts() {
		out <- ev
	}
}

func checkDevRegularFiles() []*event.Event {
	var events []*event.Event
	_ = filepath.WalkDir("/dev", func(path string, d os.DirEntry, err error) error {
		if err != nil || path == "/dev" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Mode().IsRegular() {
			events = append(events, event.New(event.TypeRootkitSuspicious, event.SevHigh, "Regular file found under /dev").
				WithSource(Name).
				WithMessage("regular files under /dev are unusual and can indicate hidden malware storage").
				WithField("path", path).
				WithField("reason", "dev_regular_file"))
		}
		return nil
	})
	return events
}

func checkPromisc() []*event.Event {
	var events []*event.Event
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		flagsPath := filepath.Join("/sys/class/net", entry.Name(), "flags")
		b, err := os.ReadFile(flagsPath)
		if err != nil {
			continue
		}
		raw := strings.TrimSpace(string(b))
		n, err := strconv.ParseInt(strings.TrimPrefix(raw, "0x"), 16, 64)
		if err != nil {
			continue
		}
		if n&0x100 != 0 {
			events = append(events, event.New(event.TypeRootkitSuspicious, event.SevHigh, "Network interface in promiscuous mode").
				WithSource(Name).
				WithField("interface", entry.Name()).
				WithField("reason", "promiscuous_interface"))
		}
	}
	return events
}

func checkHiddenPIDs() []*event.Event {
	var events []*event.Event
	for pid := 2; pid < 65535; pid++ {
		err := syscall.Kill(pid, 0)
		if err != nil {
			continue
		}
		if _, statErr := os.Stat(filepath.Join("/proc", strconv.Itoa(pid))); os.IsNotExist(statErr) {
			events = append(events, event.New(event.TypeRootkitSuspicious, event.SevCritical, "Possible hidden process").
				WithSource(Name).
				WithMessage("kill(0) can see a PID that /proc does not list").
				WithField("pid", pid).
				WithField("reason", "hidden_pid"))
		}
	}
	return events
}

func checkHiddenPorts() []*event.Event {
	procPorts := listenPortsFromProc()
	if len(procPorts) == 0 {
		return nil
	}
	cmd := exec.Command("ss", "-lnt")
	b, err := cmd.Output()
	if err != nil {
		return nil
	}
	var events []*event.Event
	for port := range procPorts {
		if !bytes.Contains(b, []byte(":"+strconv.Itoa(port))) {
			events = append(events, event.New(event.TypeRootkitSuspicious, event.SevHigh, "Possible hidden listening port").
				WithSource(Name).
				WithField("port", port).
				WithField("reason", "hidden_port"))
		}
	}
	return events
}

func checkFileSizeMismatches() []*event.Event {
	var events []*event.Event
	for _, root := range []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin"} {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil || !info.Mode().IsRegular() {
				return nil
			}
			actual, err := fileSizeBySeek(path)
			if err != nil {
				return nil
			}
			if actual != info.Size() {
				events = append(events, event.New(event.TypeRootkitSuspicious, event.SevHigh, "File size/stat mismatch").
					WithSource(Name).
					WithMessage("stat size and seek-derived file size disagree, which can indicate filesystem tampering").
					WithField("path", path).
					WithField("stat_size", info.Size()).
					WithField("seek_size", actual).
					WithField("reason", "file_size_stat_mismatch"))
			}
			return nil
		})
	}
	return events
}

func fileSizeBySeek(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.Seek(0, io.SeekEnd)
}

func listenPortsFromProc() map[int]struct{} {
	out := map[int]struct{}{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			addr := fields[1]
			i := strings.LastIndex(addr, ":")
			if i < 0 {
				continue
			}
			n, err := strconv.ParseInt(addr[i+1:], 16, 32)
			if err == nil && n > 0 {
				out[int(n)] = struct{}{}
			}
		}
	}
	return out
}

func checkDirLinkCounts() []*event.Event {
	var events []*event.Event
	for _, dir := range []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/etc"} {
		info, err := os.Stat(dir)
		if err != nil {
			continue
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Nlink < 2 {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		subdirs := uint64(2)
		for _, e := range entries {
			if e.IsDir() {
				subdirs++
			}
		}
		if st.Nlink > 0 && absDiff(uint64(st.Nlink), subdirs) > 3 {
			events = append(events, event.New(event.TypeRootkitSuspicious, event.SevMedium, "Directory link count mismatch").
				WithSource(Name).
				WithField("path", dir).
				WithField("nlink", st.Nlink).
				WithField("subdirs_plus_two", subdirs).
				WithField("reason", "dir_link_count_mismatch"))
		}
	}
	return events
}

func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

var _ = fmt.Sprintf
