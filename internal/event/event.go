package event

import (
	"encoding/json"
	"time"
)

type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Event types — the canonical taxonomy. PRD section 26.
const (
	TypeSSHLoginSuccess      = "ssh.login.success"
	TypeSSHLoginFailed       = "ssh.login.failed"
	TypeSSHInvalidUser       = "ssh.login.invalid_user"
	TypeSSHBruteforce        = "ssh.bruteforce.detected"
	TypeSSHLoginAfterFails   = "ssh.login.after_failures"
	TypeCPUSpike             = "cpu.spike"
	TypeProcessSuspicious    = "process.suspicious"
	TypeProcessHighCPU       = "process.high_cpu"
	TypeProcessKnownMiner    = "process.known_miner"
	TypeProcessWebShell      = "process.webshell"
	TypeProcessEnvTamper     = "process.env_tamper"
	TypeProcessCredAccess    = "process.credential_access"
	TypeProcessTmpOutbound   = "process.tmp_with_outbound"
	TypeProcessReinfection   = "process.reinfection_loop"
	TypeServiceExposed       = "service.exposed"
	TypeCronModified         = "cron.modified"
	TypeSSHKeyAdded          = "ssh_key.added"
	TypeUserCreated          = "user.created"
	TypeSudoerModified       = "sudoer.modified"
	TypeSystemdServiceAdded  = "systemd.service.created"
	TypeServiceBruteforce    = "service.bruteforce"
	TypeAuditSetuid          = "audit.setuid"
	TypeAuditKernelModule    = "audit.kernel_module"
	TypeAuditSensitiveFile   = "audit.sensitive_file"
	TypeRootkitSuspicious    = "rootkit.suspicious"
	TypeFIMModified          = "fim.modified"
	TypeRansomwareActivity   = "ransomware.activity"
	TypeOutboundSSHSpike     = "outbound.ssh_spike"
	TypeOutboundSMTPSpike    = "outbound.smtp_spike"
	TypeOutboundRDPSpike     = "outbound.rdp_spike"
	TypeOutboundMinerPool    = "outbound.miner_pool"
	TypeOutboundBulkTransfer = "outbound.bulk_transfer"
	TypeKnownBadConnection   = "threat.known_bad_connection"
	TypeKnownBadDomain       = "threat.known_bad_domain"
	TypeDNSAnomaly           = "dns.anomaly"
	TypeCloudMetadataAccess  = "cloud.metadata_access"
	TypeAgentStarted         = "agent.started"
	TypeAgentStopped         = "agent.stopped"
	TypeAgentHeartbeat       = "agent.heartbeat"
	TypeAgentBinaryModified  = "agent.binary_modified"
	TypeAgentError           = "agent.error"
)

type Event struct {
	Type     string         `json:"type"`
	Severity Severity       `json:"severity"`
	Time     time.Time      `json:"time"`
	Server   string         `json:"server,omitempty"`
	Source   string         `json:"source,omitempty"`
	Title    string         `json:"title"`
	Message  string         `json:"message,omitempty"`
	Fields   map[string]any `json:"fields,omitempty"`
}

func New(typ string, sev Severity, title string) *Event {
	return &Event{
		Type:     typ,
		Severity: sev,
		Time:     time.Now().UTC(),
		Title:    title,
		Fields:   map[string]any{},
	}
}

func (e *Event) WithField(k string, v any) *Event {
	if e.Fields == nil {
		e.Fields = map[string]any{}
	}
	e.Fields[k] = v
	return e
}

func (e *Event) WithMessage(msg string) *Event {
	e.Message = msg
	return e
}

func (e *Event) WithSource(src string) *Event {
	e.Source = src
	return e
}

func (e *Event) JSON() ([]byte, error) {
	return json.Marshal(e)
}
