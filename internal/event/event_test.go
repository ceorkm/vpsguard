package event

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Lock the wire format. Anything that breaks this test breaks downstream
// consumers (Telegram formatter in v0.2, anyone parsing JSONL in pipelines).
// Update deliberately, never accidentally.

func TestEventJSON_FullShape(t *testing.T) {
	ev := New(TypeSSHLoginFailed, SevHigh, "SSH login failed").
		WithSource("ssh").
		WithMessage("brute-force attempt").
		WithField("ip", "1.2.3.4").
		WithField("user", "root")
	// pin time so the assertion is stable
	ev.Time = time.Date(2026, 5, 2, 21, 14, 1, 0, time.UTC)
	ev.Server = "main-vps"

	b, err := ev.JSON()
	if err != nil {
		t.Fatal(err)
	}

	// Decode generically and assert fields. Keeps the test readable while
	// still catching field renames.
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}

	expect(t, got, "type", "ssh.login.failed")
	expect(t, got, "severity", "high")
	expect(t, got, "time", "2026-05-02T21:14:01Z")
	expect(t, got, "server", "main-vps")
	expect(t, got, "source", "ssh")
	expect(t, got, "title", "SSH login failed")
	expect(t, got, "message", "brute-force attempt")

	fields, ok := got["fields"].(map[string]any)
	if !ok {
		t.Fatalf("fields not a map: %T %v", got["fields"], got["fields"])
	}
	expect(t, fields, "ip", "1.2.3.4")
	expect(t, fields, "user", "root")
}

func TestEventJSON_OmitEmpty(t *testing.T) {
	// Minimal event: no server, no source, no message, no fields.
	ev := New(TypeAgentHeartbeat, SevInfo, "agent heartbeat")
	ev.Time = time.Date(2026, 5, 2, 21, 14, 1, 0, time.UTC)
	// Fields is initialized as empty map by New(); empty map should serialize
	// or be omitted — assert behavior.

	b, err := ev.JSON()
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)

	for _, badField := range []string{`"server"`, `"source"`, `"message"`} {
		if strings.Contains(s, badField) {
			t.Errorf("JSON should omit empty %s, got: %s", badField, s)
		}
	}

	// type, severity, time, title are always required
	for _, mustHave := range []string{`"type"`, `"severity"`, `"time"`, `"title"`} {
		if !strings.Contains(s, mustHave) {
			t.Errorf("JSON missing required %s, got: %s", mustHave, s)
		}
	}
}

func TestEventJSON_TimeIsRFC3339UTC(t *testing.T) {
	ev := New(TypeAgentHeartbeat, SevInfo, "tick")
	ev.Time = time.Date(2026, 5, 2, 21, 14, 1, 0, time.UTC)

	b, _ := ev.JSON()
	var got map[string]any
	_ = json.Unmarshal(b, &got)

	ts, _ := got["time"].(string)
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Errorf("time field not RFC3339: %q (%v)", ts, err)
	}
	if !strings.HasSuffix(ts, "Z") {
		t.Errorf("time must serialize as UTC (suffix Z), got %q", ts)
	}
}

func TestSeverityValues(t *testing.T) {
	// Wire values must be lowercase, stable strings.
	cases := map[Severity]string{
		SevInfo:     "info",
		SevLow:      "low",
		SevMedium:   "medium",
		SevHigh:     "high",
		SevCritical: "critical",
	}
	for sev, want := range cases {
		if string(sev) != want {
			t.Errorf("severity %v: got %q, want %q", sev, string(sev), want)
		}
	}
}

func TestEventTypeConstants(t *testing.T) {
	// Catch accidental rename of any wire-protocol event type.
	want := map[string]string{
		"TypeSSHLoginSuccess":      "ssh.login.success",
		"TypeSSHLoginFailed":       "ssh.login.failed",
		"TypeSSHInvalidUser":       "ssh.login.invalid_user",
		"TypeSSHBruteforce":        "ssh.bruteforce.detected",
		"TypeSSHLoginAfterFails":   "ssh.login.after_failures",
		"TypeCPUSpike":             "cpu.spike",
		"TypeProcessSuspicious":    "process.suspicious",
		"TypeProcessHighCPU":       "process.high_cpu",
		"TypeProcessKnownMiner":    "process.known_miner",
		"TypeProcessWebShell":      "process.webshell",
		"TypeProcessEnvTamper":     "process.env_tamper",
		"TypeProcessCredAccess":    "process.credential_access",
		"TypeProcessTmpOutbound":   "process.tmp_with_outbound",
		"TypeServiceExposed":       "service.exposed",
		"TypeCronModified":         "cron.modified",
		"TypeSSHKeyAdded":          "ssh_key.added",
		"TypeUserCreated":          "user.created",
		"TypeSudoerModified":       "sudoer.modified",
		"TypeSystemdServiceAdded":  "systemd.service.created",
		"TypeServiceBruteforce":    "service.bruteforce",
		"TypeAuditSetuid":          "audit.setuid",
		"TypeAuditKernelModule":    "audit.kernel_module",
		"TypeAuditSensitiveFile":   "audit.sensitive_file",
		"TypeRootkitSuspicious":    "rootkit.suspicious",
		"TypeFIMModified":          "fim.modified",
		"TypeRansomwareActivity":   "ransomware.activity",
		"TypeOutboundSSHSpike":     "outbound.ssh_spike",
		"TypeOutboundSMTPSpike":    "outbound.smtp_spike",
		"TypeOutboundRDPSpike":     "outbound.rdp_spike",
		"TypeOutboundMinerPool":    "outbound.miner_pool",
		"TypeOutboundBulkTransfer": "outbound.bulk_transfer",
		"TypeKnownBadConnection":   "threat.known_bad_connection",
		"TypeKnownBadDomain":       "threat.known_bad_domain",
		"TypeDNSAnomaly":           "dns.anomaly",
		"TypeCloudMetadataAccess":  "cloud.metadata_access",
		"TypeAgentStarted":         "agent.started",
		"TypeAgentStopped":         "agent.stopped",
		"TypeAgentHeartbeat":       "agent.heartbeat",
		"TypeAgentBinaryModified":  "agent.binary_modified",
		"TypeAgentError":           "agent.error",
	}
	got := map[string]string{
		"TypeSSHLoginSuccess":      TypeSSHLoginSuccess,
		"TypeSSHLoginFailed":       TypeSSHLoginFailed,
		"TypeSSHInvalidUser":       TypeSSHInvalidUser,
		"TypeSSHBruteforce":        TypeSSHBruteforce,
		"TypeSSHLoginAfterFails":   TypeSSHLoginAfterFails,
		"TypeCPUSpike":             TypeCPUSpike,
		"TypeProcessSuspicious":    TypeProcessSuspicious,
		"TypeProcessHighCPU":       TypeProcessHighCPU,
		"TypeProcessKnownMiner":    TypeProcessKnownMiner,
		"TypeProcessWebShell":      TypeProcessWebShell,
		"TypeProcessEnvTamper":     TypeProcessEnvTamper,
		"TypeProcessCredAccess":    TypeProcessCredAccess,
		"TypeProcessTmpOutbound":   TypeProcessTmpOutbound,
		"TypeServiceExposed":       TypeServiceExposed,
		"TypeCronModified":         TypeCronModified,
		"TypeSSHKeyAdded":          TypeSSHKeyAdded,
		"TypeUserCreated":          TypeUserCreated,
		"TypeSudoerModified":       TypeSudoerModified,
		"TypeSystemdServiceAdded":  TypeSystemdServiceAdded,
		"TypeServiceBruteforce":    TypeServiceBruteforce,
		"TypeAuditSetuid":          TypeAuditSetuid,
		"TypeAuditKernelModule":    TypeAuditKernelModule,
		"TypeAuditSensitiveFile":   TypeAuditSensitiveFile,
		"TypeRootkitSuspicious":    TypeRootkitSuspicious,
		"TypeFIMModified":          TypeFIMModified,
		"TypeRansomwareActivity":   TypeRansomwareActivity,
		"TypeOutboundSSHSpike":     TypeOutboundSSHSpike,
		"TypeOutboundSMTPSpike":    TypeOutboundSMTPSpike,
		"TypeOutboundRDPSpike":     TypeOutboundRDPSpike,
		"TypeOutboundMinerPool":    TypeOutboundMinerPool,
		"TypeOutboundBulkTransfer": TypeOutboundBulkTransfer,
		"TypeKnownBadConnection":   TypeKnownBadConnection,
		"TypeKnownBadDomain":       TypeKnownBadDomain,
		"TypeDNSAnomaly":           TypeDNSAnomaly,
		"TypeCloudMetadataAccess":  TypeCloudMetadataAccess,
		"TypeAgentStarted":         TypeAgentStarted,
		"TypeAgentStopped":         TypeAgentStopped,
		"TypeAgentHeartbeat":       TypeAgentHeartbeat,
		"TypeAgentBinaryModified":  TypeAgentBinaryModified,
		"TypeAgentError":           TypeAgentError,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: got %q, want %q", k, got[k], w)
		}
	}
}

func expect(t *testing.T, m map[string]any, key, want string) {
	t.Helper()
	got, ok := m[key].(string)
	if !ok {
		t.Errorf("key %q: not a string (got %T %v)", key, m[key], m[key])
		return
	}
	if got != want {
		t.Errorf("key %q: got %q, want %q", key, got, want)
	}
}
