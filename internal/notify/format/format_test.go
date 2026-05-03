package format

import (
	"strings"
	"testing"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
)

func evt(typ string, sev event.Severity, title, server string, fields map[string]any) *event.Event {
	e := event.New(typ, sev, title)
	e.Server = server
	e.Time = time.Date(2026, 5, 2, 21, 14, 1, 0, time.UTC)
	for k, v := range fields {
		e.WithField(k, v)
	}
	return e
}

func TestFormat_SSHLoginSuccess(t *testing.T) {
	out := Format(evt(event.TypeSSHLoginSuccess, event.SevHigh, "SSH login (publickey)",
		"main-vps", map[string]any{"user": "root", "ip": "1.2.3.4"}))
	mustContain(t, out, "*New SSH login*")
	mustContain(t, out, "*Server:* main\\-vps")
	mustContain(t, out, "*User:* root")
	mustContain(t, out, "*IP:* 1\\.2\\.3\\.4")
	mustContain(t, out, "2026\\-05\\-02 21:14 UTC")
}

func TestFormat_SSHFailed(t *testing.T) {
	out := Format(evt(event.TypeSSHLoginFailed, event.SevLow, "SSH login failed",
		"main-vps", map[string]any{"user": "admin", "ip": "45.227.255.215"}))
	mustContain(t, out, "*SSH login failed*")
	mustContain(t, out, "*User:* admin")
	mustContain(t, out, "*IP:* 45\\.227\\.255\\.215")
}

func TestFormat_KnownMiner(t *testing.T) {
	e := evt(event.TypeProcessKnownMiner, event.SevHigh, "Possible crypto miner running",
		"main-vps", map[string]any{"exe": "/var/tmp/xmrig", "cmdline": "/var/tmp/xmrig --donate-level 1", "pid": 8421})
	e.WithMessage("process name or cmdline matches a known crypto-miner pattern")
	out := Format(e)
	mustContain(t, out, "*Possible crypto miner detected*")
	mustContain(t, out, "*Process:* `/var/tmp/xmrig`")
	mustContain(t, out, "*Cmdline:*")
	mustContain(t, out, "*PID:* 8421")
}

func TestFormat_SuspiciousProcess(t *testing.T) {
	e := evt(event.TypeProcessSuspicious, event.SevHigh, "Suspicious process running from temporary path",
		"main-vps", map[string]any{"exe": "/tmp/sleep", "pid": 1234, "reason": "exe_in_tmp"})
	out := Format(e)
	mustContain(t, out, "*Suspicious process detected*")
	mustContain(t, out, "*Process:* `/tmp/sleep`")
	mustContain(t, out, "*Reason:* exe\\_in\\_tmp")
}

func TestFormat_HighCPUProcess(t *testing.T) {
	e := evt(event.TypeProcessHighCPU, event.SevHigh, "Process using sustained high CPU",
		"main-vps", map[string]any{"exe": "/var/tmp/x", "pid": 777, "usage_pct": 91.2, "sustained_seconds": 190})
	e.WithMessage("process has used at least 70% CPU for 3m0s")
	out := Format(e)
	mustContain(t, out, "*Process using high CPU*")
	mustContain(t, out, "*Process:* `/var/tmp/x`")
	mustContain(t, out, "*Usage:* 91\\.2%")
}

func TestFormat_AgentBinaryModified(t *testing.T) {
	out := Format(evt(event.TypeAgentBinaryModified, event.SevCritical, "vpsguard binary changed on disk",
		"main-vps", map[string]any{"path": "/usr/local/bin/vpsguard"}))
	mustContain(t, out, "*vpsguard binary changed*")
	mustContain(t, out, "*Path:* `/usr/local/bin/vpsguard`")
}

func TestFormat_CPUSpike(t *testing.T) {
	e := evt(event.TypeCPUSpike, event.SevHigh, "Sustained high CPU usage",
		"main-vps", map[string]any{"usage_pct": 97.5, "sustained_seconds": 360, "threshold_pct": 90.0})
	e.WithMessage("CPU has been at or above 90% for 300 seconds")
	out := Format(e)
	mustContain(t, out, "*Sustained CPU spike*")
	mustContain(t, out, "*Usage:* 97\\.5%")
	mustContain(t, out, "*Sustained:* 360 seconds")
}

func TestFormat_OutboundMinerPool(t *testing.T) {
	e := evt(event.TypeOutboundMinerPool, event.SevHigh, "Possible crypto-miner pool connection",
		"main-vps", map[string]any{"unique_dst_ips": 1, "ports": "3333, 4444", "window": "10m0s"})
	out := Format(e)
	mustContain(t, out, "*Possible mining pool connection*")
	mustContain(t, out, "*Remote IPs:* 1")
	mustContain(t, out, "*Ports:* 3333, 4444")
}

func TestFormat_OutboundRDP(t *testing.T) {
	e := evt(event.TypeOutboundRDPSpike, event.SevHigh, "Possible outbound RDP brute-force from this server",
		"main-vps", map[string]any{"unique_dst_ips": 22, "port": 3389, "window": "10m0s"})
	out := Format(e)
	mustContain(t, out, "*Possible outbound RDP abuse*")
	mustContain(t, out, "*Port:* 3389")
}

func TestFormat_CronModified(t *testing.T) {
	out := Format(evt(event.TypeCronModified, event.SevHigh, "Cron drop-in directory changed",
		"main-vps", map[string]any{"path": "/etc/cron.d/update", "op": "CREATE"}))
	mustContain(t, out, "*New or modified cron job*")
	mustContain(t, out, "*Path:* `/etc/cron.d/update`")
	mustContain(t, out, "*Op:* CREATE")
	mustContain(t, out, "persistence")
}

func TestFormat_SSHKeyAdded(t *testing.T) {
	out := Format(evt(event.TypeSSHKeyAdded, event.SevCritical, "Root authorized_keys modified",
		"main-vps", map[string]any{"path": "/root/.ssh/authorized_keys", "op": "WRITE"}))
	mustContain(t, out, "*SSH key file changed*")
	mustContain(t, out, "*Path:* `/root/.ssh/authorized_keys`")
}

func TestFormat_AgentError(t *testing.T) {
	e := evt(event.TypeAgentError, event.SevHigh, `detector "ssh" failed`,
		"main-vps", map[string]any{"detector": "ssh", "error": "no such file"})
	e.WithMessage("ssh: auth log /var/log/auth.log does not exist")
	out := Format(e)
	mustContain(t, out, "*vpsguard detector error*")
	mustContain(t, out, "*Detector:* ssh")
	mustContain(t, out, "auth log")
}

func TestFormat_AgentStarted(t *testing.T) {
	out := Format(evt(event.TypeAgentStarted, event.SevInfo, "vpsguard agent started",
		"main-vps", nil))
	mustContain(t, out, "vpsguard started")
	mustContain(t, out, "*Server:* main\\-vps")
}

func TestFormat_GenericFallback(t *testing.T) {
	// An event type without a specific template still produces output
	// (no panic, no empty string).
	out := Format(evt("unknown.type", event.SevMedium, "Strange thing happened",
		"main-vps", map[string]any{"detail": "uh oh"}))
	if out == "" {
		t.Fatal("generic format produced empty output")
	}
	mustContain(t, out, "Strange thing happened")
}

func TestFormat_NilEvent(t *testing.T) {
	if Format(nil) != "" {
		t.Error("Format(nil) should return empty string")
	}
}

// Make sure we didn't leak literal MarkdownV2 reserved chars from
// user-supplied data (regression for "user.name with dots").
func TestFormat_EscapesUserSuppliedDots(t *testing.T) {
	out := Format(evt(event.TypeSSHLoginFailed, event.SevLow, "SSH login failed",
		"my.vps.name", map[string]any{"user": "git.user", "ip": "10.0.0.1"}))
	if strings.Contains(out, "git.user") {
		t.Errorf("dot in user not escaped:\n%s", out)
	}
	if strings.Contains(out, "my.vps.name") {
		t.Errorf("dot in server not escaped:\n%s", out)
	}
	if strings.Contains(out, "10.0.0.1") {
		t.Errorf("dot in ip not escaped:\n%s", out)
	}
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected %q in output:\n%s", needle, haystack)
	}
}
