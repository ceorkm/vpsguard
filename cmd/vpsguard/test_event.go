package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ceorkm/vpsguard/internal/agent"
	"github.com/ceorkm/vpsguard/internal/config"
	"github.com/ceorkm/vpsguard/internal/event"
	"github.com/ceorkm/vpsguard/internal/notify/telegram"
)

func testEventCmd(args []string) {
	fs := flag.NewFlagSet("test-event", flag.ExitOnError)
	configPath := fs.String("config", config.DefaultPath, "path to config.yml")
	kind := fs.String("type", "all", "event type: all|ssh-login|bruteforce|miner|cron|outbound|rdp|known-bad|dns|exposure|tamper")
	sendTelegram := fs.Bool("telegram", false, "also send synthetic events to Telegram if configured")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fatalf("test-event: load config: %v", err)
	}

	sinks := []agent.Sink{agent.NewStdoutSink(os.Stdout)}
	if *sendTelegram {
		if !cfg.Telegram.Configured() {
			fatalf("test-event: Telegram is not configured")
		}
		sinks = append(sinks, agent.NewTelegramSink(&telegram.Sender{
			BotToken: cfg.Telegram.BotToken,
			ChatID:   cfg.Telegram.ChatID,
		}, event.SevInfo))
	}
	events, err := syntheticEvents(*kind, cfg.ServerName)
	if err != nil {
		fatalf("test-event: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, ev := range events {
		for _, sink := range sinks {
			if err := sink.Send(ctx, ev); err != nil {
				fatalf("test-event: sink %s: %v", sink.Name(), err)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "emitted %d synthetic event(s)\n", len(events))
}

func syntheticEvents(kind, server string) ([]*event.Event, error) {
	var out []*event.Event
	add := func(e *event.Event) {
		e.Server = server
		e.Time = time.Now().UTC()
		out = append(out, e)
	}
	if kind == "all" || kind == "ssh-login" {
		add(event.New(event.TypeSSHLoginSuccess, event.SevHigh, "SSH login (publickey)").
			WithSource("test-event").
			WithField("user", "root").
			WithField("ip", "203.0.113.10").
			WithField("method", "publickey").
			WithField("first_seen", true))
	}
	if kind == "all" || kind == "bruteforce" {
		add(event.New(event.TypeSSHBruteforce, event.SevHigh, "SSH brute-force attack detected").
			WithSource("test-event").
			WithField("ip", "198.51.100.44").
			WithField("failed_attempts", 72).
			WithField("distinct_users", 6).
			WithField("window", "5m0s"))
	}
	if kind == "all" || kind == "miner" {
		add(event.New(event.TypeProcessKnownMiner, event.SevHigh, "Possible crypto miner running").
			WithSource("test-event").
			WithMessage("process name or cmdline matches a known crypto-miner pattern").
			WithField("pid", 8421).
			WithField("exe", "/var/tmp/xmrig").
			WithField("cmdline", "/var/tmp/xmrig --donate-level 1"))
	}
	if kind == "all" || kind == "cron" {
		add(event.New(event.TypeCronModified, event.SevHigh, "Cron drop-in directory changed").
			WithSource("test-event").
			WithField("path", "/etc/cron.d/update").
			WithField("op", "CREATE"))
	}
	if kind == "all" || kind == "outbound" {
		add(event.New(event.TypeOutboundSSHSpike, event.SevHigh, "Possible outbound SSH brute-force from this server").
			WithSource("test-event").
			WithField("unique_dst_ips", 80).
			WithField("port", 22).
			WithField("window", "10m0s"))
	}
	if kind == "all" || kind == "rdp" {
		add(event.New(event.TypeOutboundRDPSpike, event.SevHigh, "Possible outbound RDP brute-force from this server").
			WithSource("test-event").
			WithField("unique_dst_ips", 25).
			WithField("port", 3389).
			WithField("window", "10m0s"))
	}
	if kind == "all" || kind == "known-bad" {
		add(event.New(event.TypeKnownBadConnection, event.SevCritical, "Outbound connection to known-bad IP").
			WithSource("test-event").
			WithField("ip", "203.0.113.66").
			WithField("port", 443))
		add(event.New(event.TypeKnownBadDomain, event.SevCritical, "DNS query for known-bad domain").
			WithSource("test-event").
			WithField("domain", "payload.malware.example").
			WithField("matched_domain", "malware.example"))
	}
	if kind == "all" || kind == "dns" {
		add(event.New(event.TypeDNSAnomaly, event.SevHigh, "Possible DNS tunneling activity").
			WithSource("test-event").
			WithField("domain", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.example").
			WithField("base_domain", "evil.example").
			WithField("reason", "long_label").
			WithField("queries", 38).
			WithField("window", "5m0s"))
	}
	if kind == "all" || kind == "exposure" {
		add(event.New(event.TypeServiceExposed, event.SevCritical, "Risky service exposed publicly").
			WithSource("test-event").
			WithMessage("unauthenticated Docker APIs are routinely abused to mount the host filesystem and drop miners or bot tooling").
			WithField("service", "Docker API").
			WithField("ip", "0.0.0.0").
			WithField("port", 2375))
	}
	if kind == "all" || kind == "tamper" {
		add(event.New(event.TypeAgentBinaryModified, event.SevCritical, "vpsguard binary changed on disk").
			WithSource("test-event").
			WithField("path", "/usr/local/bin/vpsguard"))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("unknown synthetic event type %q", kind)
	}
	return out, nil
}
