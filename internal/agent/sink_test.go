package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ceorkm/vpsguard/internal/event"
	"github.com/ceorkm/vpsguard/internal/notify/telegram"
)

func TestTelegramSink_SuppressesBelowSeverity(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	sink := NewTelegramSink(&telegram.Sender{
		BotToken: "T",
		ChatID:   "1",
		APIBase:  srv.URL,
	}, event.SevCritical)

	err := sink.Send(context.Background(), event.New(event.TypeCPUSpike, event.SevLow, "low cpu"))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("expected low severity event to be suppressed, got %d sends", calls)
	}
}

func TestTelegramSink_AgentErrorBypassesSeverityGate(t *testing.T) {
	calls := 0
	var payload struct {
		Text string `json:"text"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	sink := NewTelegramSink(&telegram.Sender{
		BotToken: "T",
		ChatID:   "1",
		APIBase:  srv.URL,
	}, event.SevCritical)

	err := sink.Send(context.Background(), event.New(event.TypeAgentError, event.SevInfo, "detector failed"))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("expected agent.error to send despite severity gate, got %d sends", calls)
	}
	if payload.Text == "" {
		t.Fatal("expected Telegram payload text")
	}
}
