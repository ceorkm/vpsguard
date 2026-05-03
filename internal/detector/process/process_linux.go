//go:build linux

package process

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
)

const scanInterval = 10 * time.Second

type pidState struct {
	staticAlerted  bool
	lastJiffies    uint64
	lastTotal      uint64
	aboveSince     time.Time
	highCPUAlerted bool
}

func run(ctx context.Context, out chan<- *event.Event, d *Detector) error {
	state := map[int]*pidState{}
	threshold := d.HighCPUThreshold
	if threshold <= 0 {
		threshold = 50 // any single process holding ≥50% of one core sustained = suspect
	}
	sustain := d.HighCPUSustain
	if sustain <= 0 {
		sustain = 3 * time.Minute
	}
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			scan(state, threshold, sustain, out)
		}
	}
}

func scan(state map[int]*pidState, threshold float64, sustain time.Duration, out chan<- *event.Event) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	total, _ := readTotalJiffies()
	alive := map[int]struct{}{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		alive[pid] = struct{}{}
		st := state[pid]
		if st == nil {
			st = &pidState{}
			state[pid] = st
		}
		if !st.staticAlerted {
			if ev := inspect(pid); ev != nil {
				st.staticAlerted = true
				out <- ev
			}
		}
		if ev := inspectCPU(pid, st, total, threshold, sustain); ev != nil {
			out <- ev
		}
	}
	for pid := range state {
		if _, ok := alive[pid]; !ok {
			delete(state, pid)
		}
	}
}

func inspect(pid int) *event.Event {
	exe, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return nil
	}

	deleted := strings.HasSuffix(exe, " (deleted)")
	cleanExe := strings.TrimSuffix(exe, " (deleted)")
	cmdline := readCmdline(pid)
	procName := baseName(cleanExe)
	env := readEnviron(pid)

	if isMiner(procName) || cmdlineHasMiner(cmdline) {
		return event.New(event.TypeProcessKnownMiner, event.SevHigh,
			"Possible crypto miner running").
			WithSource(Name).
			WithMessage("process name or cmdline matches a known crypto-miner pattern").
			WithField("pid", pid).
			WithField("exe", cleanExe).
			WithField("cmdline", cmdline)
	}

	if reason := suspiciousCommand(cmdline); reason != "" {
		return event.New(event.TypeProcessSuspicious, event.SevCritical,
			"Suspicious command execution").
			WithSource(Name).
			WithMessage("process command line matches a reverse-shell or attacker-tool pattern").
			WithField("pid", pid).
			WithField("exe", cleanExe).
			WithField("cmdline", cmdline).
			WithField("reason", reason)
	}

	if isShell(procName) && parentLooksLikeWeb(pid) {
		return event.New(event.TypeProcessWebShell, event.SevCritical,
			"Shell spawned by web server process").
			WithSource(Name).
			WithMessage("a web server or app runtime spawned an interactive shell — common webshell/RCE behavior").
			WithField("pid", pid).
			WithField("exe", cleanExe).
			WithField("cmdline", cmdline).
			WithField("reason", "web_parent_shell")
	}

	if reason := suspiciousEnv(env); reason != "" {
		return event.New(event.TypeProcessEnvTamper, event.SevHigh,
			"Suspicious process environment").
			WithSource(Name).
			WithMessage("process environment contains shell-history or preload tampering indicators").
			WithField("pid", pid).
			WithField("exe", cleanExe).
			WithField("cmdline", cmdline).
			WithField("reason", reason)
	}

	// Sensitive-file access by any process. Native /proc/PID/fd scan;
	// no auditd or eBPF dependency. Catches stealers that hold an open
	// fd on /etc/shadow, ~/.ssh/id_rsa, ~/.aws/credentials, etc.
	if path := scanFDsForSensitive(pid); path != "" {
		return event.New(event.TypeProcessCredAccess, event.SevCritical,
			"Process has a sensitive credential file open").
			WithSource(Name).
			WithMessage("a process is currently holding a known credential or secret file open — possible info-stealer").
			WithField("pid", pid).
			WithField("exe", cleanExe).
			WithField("cmdline", cmdline).
			WithField("path", path)
	}

	for _, p := range suspiciousPrefixes {
		if strings.HasPrefix(cleanExe, p) {
			// Combo rule: /tmp binary + outbound public socket = critical.
			// This is the universal "drop in /tmp, dial home" pattern that
			// virtually every miner / stealer / botnet implant exhibits.
			if hasOutboundSocket(pid) {
				return event.New(event.TypeProcessTmpOutbound, event.SevCritical,
					"Suspicious process from /tmp making outbound connection").
					WithSource(Name).
					WithMessage("a binary in a writable temp directory has at least one connection to a public IP — almost certainly attacker-deployed").
					WithField("pid", pid).
					WithField("exe", cleanExe).
					WithField("cmdline", cmdline).
					WithField("reason", "exe_in_tmp_with_outbound")
			}
			return event.New(event.TypeProcessSuspicious, event.SevHigh,
				"Suspicious process running from temporary path").
				WithSource(Name).
				WithMessage("process executable resides in a writable temp directory commonly used by attackers").
				WithField("pid", pid).
				WithField("exe", cleanExe).
				WithField("cmdline", cmdline).
				WithField("reason", "exe_in_tmp")
		}
	}

	if deleted {
		return event.New(event.TypeProcessSuspicious, event.SevHigh,
			"Process running a deleted binary").
			WithSource(Name).
			WithMessage("the executable file backing this process has been unlinked from disk").
			WithField("pid", pid).
			WithField("exe", cleanExe).
			WithField("cmdline", cmdline).
			WithField("reason", "exe_deleted")
	}

	return nil
}

func readCmdline(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return ""
	}
	for i, c := range b {
		if c == 0 {
			b[i] = ' '
		}
	}
	return strings.TrimSpace(string(b))
}

func readEnviron(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
	if err != nil {
		return ""
	}
	for i, c := range b {
		if c == 0 {
			b[i] = ' '
		}
	}
	return strings.TrimSpace(string(b))
}

func parentLooksLikeWeb(pid int) bool {
	ppid, err := readPPID(pid)
	if err != nil || ppid <= 1 {
		return false
	}
	for depth := 0; depth < 4 && ppid > 1; depth++ {
		name := processName(ppid)
		if isWebProcess(name) {
			return true
		}
		next, err := readPPID(ppid)
		if err != nil {
			return false
		}
		ppid = next
	}
	return false
}

func readPPID(pid int) (int, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) < 4 {
		return 0, fmt.Errorf("malformed proc stat")
	}
	return strconv.Atoi(fields[3])
}

func processName(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err == nil {
		return strings.TrimSpace(string(b))
	}
	return baseName(readCmdline(pid))
}

func inspectCPU(pid int, st *pidState, total uint64, threshold float64, sustain time.Duration) *event.Event {
	if total == 0 {
		return nil
	}
	proc, err := readProcJiffies(pid)
	if err != nil {
		return nil
	}
	if st.lastJiffies == 0 || st.lastTotal == 0 {
		st.lastJiffies = proc
		st.lastTotal = total
		return nil
	}
	deltaProc := proc - st.lastJiffies
	deltaTotal := total - st.lastTotal
	st.lastJiffies = proc
	st.lastTotal = total
	if deltaTotal == 0 {
		return nil
	}
	usage := float64(deltaProc) / float64(deltaTotal) * float64(runtime.NumCPU()) * 100
	now := time.Now()
	if usage < threshold {
		st.aboveSince = time.Time{}
		st.highCPUAlerted = false
		return nil
	}
	if st.aboveSince.IsZero() {
		st.aboveSince = now
		return nil
	}
	if st.highCPUAlerted || now.Sub(st.aboveSince) < sustain {
		return nil
	}
	st.highCPUAlerted = true
	exe, _ := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	exe = strings.TrimSuffix(exe, " (deleted)")
	cmdline := readCmdline(pid)
	return event.New(event.TypeProcessHighCPU, event.SevHigh,
		"Process using sustained high CPU").
		WithSource(Name).
		WithMessage(fmt.Sprintf("process has used at least %.0f%% CPU for %s", threshold, sustain)).
		WithField("pid", pid).
		WithField("exe", exe).
		WithField("cmdline", cmdline).
		WithField("usage_pct", usage).
		WithField("threshold_pct", threshold).
		WithField("sustained_seconds", int(now.Sub(st.aboveSince).Seconds()))
}

func readProcJiffies(pid int) (uint64, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) < 15 {
		return 0, fmt.Errorf("malformed proc stat")
	}
	utime, err := strconv.ParseUint(fields[13], 10, 64)
	if err != nil {
		return 0, err
	}
	stime, err := strconv.ParseUint(fields[14], 10, 64)
	if err != nil {
		return 0, err
	}
	return utime + stime, nil
}

func readTotalJiffies() (uint64, error) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		var total uint64
		for _, field := range strings.Fields(line)[1:] {
			n, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				return 0, err
			}
			total += n
		}
		return total, nil
	}
	return 0, fmt.Errorf("cpu line missing")
}
