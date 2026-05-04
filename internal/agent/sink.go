package agent

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"sync"

	"github.com/ceorkm/vpsguard/internal/config"
	"github.com/ceorkm/vpsguard/internal/event"
	"github.com/ceorkm/vpsguard/internal/notify/format"
	"github.com/ceorkm/vpsguard/internal/notify/telegram"
)

// Sink consumes events. Implementations: stdout JSONL, Telegram.
type Sink interface {
	Name() string
	Send(ctx context.Context, e *event.Event) error
}

// --- stdout sink ---

type StdoutSink struct {
	W   io.Writer
	mu  sync.Mutex
	enc *json.Encoder
}

func NewStdoutSink(w io.Writer) *StdoutSink {
	return &StdoutSink{W: w, enc: json.NewEncoder(w)}
}

func (s *StdoutSink) Name() string { return "stdout" }
func (s *StdoutSink) Send(_ context.Context, e *event.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(e)
}

// --- Telegram sink ---

type TelegramSink struct {
	Sender      *telegram.Sender
	MinSeverity event.Severity
}

func NewTelegramSink(s *telegram.Sender, min event.Severity) *TelegramSink {
	return &TelegramSink{Sender: s, MinSeverity: min}
}

func (t *TelegramSink) Name() string { return "telegram" }

func (t *TelegramSink) Send(ctx context.Context, e *event.Event) error {
	if e == nil {
		return nil
	}
	// Severity gate: a Telegram ping for every "info"-level heartbeat
	// would be useless noise. Keep stdout for everything; Telegram for
	// what actually matters. agent.error bypasses this gate because
	// "monitoring is broken" must always reach the user.
	if e.Type != event.TypeAgentError &&
		config.SeverityRank(e.Severity) < config.SeverityRank(t.MinSeverity) {
		return nil
	}
	if !telegramWorthy(e) {
		return nil
	}
	text := format.Format(e)
	if text == "" {
		return nil
	}
	if err := t.Sender.Send(ctx, text); err != nil {
		log.Printf("telegram sink: %v", err)
		return err
	}
	return nil
}

func telegramWorthy(e *event.Event) bool {
	if e == nil {
		return false
	}
	switch e.Type {
	case event.TypeAgentError, event.TypeAgentBinaryModified:
		return true
	case event.TypeSSHBruteforce, event.TypeSSHLoginAfterFails, event.TypeServiceBruteforce:
		return true
	case event.TypeSSHLoginSuccess:
		return boolField(e, "first_seen") || boolField(e, "root_login") || boolField(e, "password_login")
	case event.TypeCronModified, event.TypeSSHKeyAdded, event.TypeUserCreated,
		event.TypeSudoerModified, event.TypeSystemdServiceAdded:
		return config.SeverityRank(e.Severity) >= config.SeverityRank(event.SevHigh)
	case event.TypeProcessKnownMiner, event.TypeProcessWebShell,
		event.TypeProcessTmpOutbound, event.TypeProcessCredAccess:
		return true
	case event.TypeProcessSuspicious:
		return highConfidenceProcessReason(stringField(e, "reason"))
	case event.TypeOutboundSSHSpike, event.TypeOutboundSMTPSpike, event.TypeOutboundRDPSpike,
		event.TypeOutboundMinerPool, event.TypeOutboundBulkTransfer, event.TypeCloudMetadataAccess,
		event.TypeKnownBadConnection, event.TypeKnownBadDomain:
		return true
	case event.TypeAuditSetuid, event.TypeAuditKernelModule, event.TypeAuditSensitiveFile,
		event.TypeRootkitSuspicious:
		return true
	case event.TypeFIMModified:
		return stringField(e, "change") != ""
	case event.TypeRansomwareActivity:
		reason := stringField(e, "reason")
		return reason == "ransomware_filename" || reason == "mass_rename_delete"
	default:
		return false
	}
}

func highConfidenceProcessReason(reason string) bool {
	switch reason {
	case "dev_tcp_reverse_shell", "netcat_exec", "ncat_exec", "socat_exec",
		"downloader_piped_to_shell", "encoded_shell_payload",
		"tor_onion_downloader", "suspicious_docker_host_access":
		return true
	default:
		return false
	}
}

func stringField(e *event.Event, key string) string {
	if e == nil || e.Fields == nil {
		return ""
	}
	v, ok := e.Fields[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func boolField(e *event.Event, key string) bool {
	if e == nil || e.Fields == nil {
		return false
	}
	v, ok := e.Fields[key]
	if !ok {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true"
	default:
		return false
	}
}
