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
