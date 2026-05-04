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

func TestTelegramWorthySuppressesNoisyFalsePositiveClasses(t *testing.T) {
	cases := []*event.Event{
		event.New(event.TypeProcessSuspicious, event.SevHigh, "deleted binary").
			WithField("exe", "/usr/local/bin/vpsguard").
			WithField("reason", "exe_deleted"),
		event.New(event.TypeProcessSuspicious, event.SevHigh, "tmp binary").
			WithField("exe", "/tmp/build-tool").
			WithField("reason", "exe_in_tmp"),
		event.New(event.TypeProcessReinfection, event.SevCritical, "sudo loop").
			WithField("exe", "/usr/bin/sudo"),
		event.New(event.TypeRansomwareActivity, event.SevCritical, "old mass write alert").
			WithField("reason", "mass_file_activity"),
		event.New(event.TypeFIMModified, event.SevMedium, "sshd permits root login").
			WithField("path", "/etc/ssh/sshd_config").
			WithField("setting", "PermitRootLogin").
			WithField("value", "yes"),
		event.New(event.TypeServiceExposed, event.SevHigh, "Redis exposed").
			WithField("service", "redis"),
		event.New(event.TypeDNSAnomaly, event.SevHigh, "Possible DNS tunneling").
			WithField("reason", "long_label"),
	}
	for _, ev := range cases {
		if telegramWorthy(ev) {
			t.Fatalf("expected %s/%s to stay local-only", ev.Type, stringField(ev, "reason"))
		}
	}
}

func TestTelegramWorthyAllowsHighConfidenceAlerts(t *testing.T) {
	cases := []*event.Event{
		event.New(event.TypeSSHLoginSuccess, event.SevHigh, "new root login").
			WithField("root_login", true),
		event.New(event.TypeSSHBruteforce, event.SevHigh, "brute force"),
		event.New(event.TypeSSHKeyAdded, event.SevCritical, "authorized_keys changed"),
		event.New(event.TypeCronModified, event.SevCritical, "cron payload"),
		event.New(event.TypeProcessKnownMiner, event.SevHigh, "miner"),
		event.New(event.TypeProcessSuspicious, event.SevCritical, "reverse shell").
			WithField("reason", "dev_tcp_reverse_shell"),
		event.New(event.TypeProcessTmpOutbound, event.SevCritical, "tmp outbound"),
		event.New(event.TypeKnownBadConnection, event.SevCritical, "bad IP"),
		event.New(event.TypeFIMModified, event.SevHigh, "sensitive file modified").
			WithField("change", "modified"),
		event.New(event.TypeRansomwareActivity, event.SevCritical, "ransom note").
			WithField("reason", "ransomware_filename"),
		event.New(event.TypeRansomwareActivity, event.SevCritical, "mass rename").
			WithField("reason", "mass_rename_delete"),
	}
	for _, ev := range cases {
		if !telegramWorthy(ev) {
			t.Fatalf("expected %s/%s to notify Telegram", ev.Type, stringField(ev, "reason"))
		}
	}
}

func TestTelegramSink_DoesNotSendLocalOnlyEventsEvenWhenSeverityMatches(t *testing.T) {
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
	}, event.SevMedium)

	ev := event.New(event.TypeProcessSuspicious, event.SevHigh, "Process running a deleted binary").
		WithField("exe", "/usr/local/bin/vpsguard").
		WithField("reason", "exe_deleted")
	if err := sink.Send(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("local-only event should not hit Telegram, got %d sends", calls)
	}
}
