// vpsguard — single-binary VPS security agent.
//
// Subcommands:
//
//	run         tail logs, watch /proc + filesystem, emit JSONL to stdout
//	            and (if configured) Telegram messages
//	test-alert  send a synthetic alert to the configured Telegram chat
//	test-event  emit synthetic detector events
//	install     install this binary as a systemd VPS agent
//	uninstall   remove the systemd VPS agent
//	update      opt-in binary updater
//	status      show systemd service status
//	logs        show journald logs
//	version     print version
//	help        usage
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"path/filepath"

	"github.com/ceorkm/vpsguard/internal/agent"
	"github.com/ceorkm/vpsguard/internal/config"
	"github.com/ceorkm/vpsguard/internal/correlate"
	"github.com/ceorkm/vpsguard/internal/detector"
	"github.com/ceorkm/vpsguard/internal/detector/audit"
	"github.com/ceorkm/vpsguard/internal/detector/cpu"
	"github.com/ceorkm/vpsguard/internal/detector/dns"
	"github.com/ceorkm/vpsguard/internal/detector/filewatch"
	"github.com/ceorkm/vpsguard/internal/detector/fim"
	"github.com/ceorkm/vpsguard/internal/detector/logpattern"
	"github.com/ceorkm/vpsguard/internal/detector/network"
	"github.com/ceorkm/vpsguard/internal/detector/process"
	"github.com/ceorkm/vpsguard/internal/detector/ransomware"
	"github.com/ceorkm/vpsguard/internal/detector/rootkit"
	"github.com/ceorkm/vpsguard/internal/detector/selfhash"
	"github.com/ceorkm/vpsguard/internal/detector/ssh"
	"github.com/ceorkm/vpsguard/internal/event"
	"github.com/ceorkm/vpsguard/internal/heartbeat"
	"github.com/ceorkm/vpsguard/internal/notify/telegram"
)

const version = "0.3.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		runCmd(os.Args[2:])
	case "configure":
		configureCmd(os.Args[2:])
	case "test-alert":
		testAlertCmd(os.Args[2:])
	case "test-event":
		testEventCmd(os.Args[2:])
	case "install":
		installCmd(os.Args[2:])
	case "uninstall":
		uninstallCmd(os.Args[2:])
	case "update":
		updateCmd(os.Args[2:])
	case "status":
		systemctlCmd("status", "vpsguard", "--no-pager")
	case "logs":
		journalctlCmd(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("vpsguard " + version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `vpsguard — VPS security agent

Usage:
  vpsguard run [flags]          start the agent
  vpsguard configure [flags]    interactive Telegram setup (writes config.yml)
  vpsguard test-alert [flags]   send a test alert to Telegram
  vpsguard test-event [flags]   emit synthetic detector events
  vpsguard install [flags]      install this binary as a systemd service
  vpsguard uninstall [flags]    remove the systemd service and binary
  vpsguard update [flags]       download and replace binary from GitHub release
  vpsguard status               show systemd service status
  vpsguard logs [--follow]      show recent service logs
  vpsguard version
  vpsguard help

Run 'vpsguard run --help' for runtime flags.`)
}

func systemctlCmd(args ...string) {
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "vpsguard: systemctl failed: %v\n", err)
		os.Exit(1)
	}
}

func journalctlCmd(args []string) {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	follow := fs.Bool("follow", false, "follow logs")
	f := fs.Bool("f", false, "follow logs")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	jargs := []string{"-u", "vpsguard", "-n", "100", "--no-pager"}
	if *follow || *f {
		jargs = append(jargs, "-f")
	}
	cmd := exec.Command("journalctl", jargs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "vpsguard: journalctl failed: %v\n", err)
		os.Exit(1)
	}
}

// runCmd is the main agent entrypoint.
func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", config.DefaultPath, "path to config.yml")
	authLogOverride := fs.String("auth-log", "", "override config: SSH auth log path; '-' reads stdin")
	disableSSH := fs.Bool("no-ssh", false, "disable SSH detector")
	disableProcess := fs.Bool("no-process", false, "disable process detector")
	disableCPU := fs.Bool("no-cpu", false, "disable CPU detector")
	disableFilewatch := fs.Bool("no-filewatch", false, "disable filesystem watcher")
	disableHeartbeat := fs.Bool("no-heartbeat", false, "disable heartbeat events")
	disableSelfhash := fs.Bool("no-selfhash", false, "disable agent binary tamper detector")
	disableTelegram := fs.Bool("no-telegram", false, "disable Telegram delivery (stdout only)")
	disableNetwork := fs.Bool("no-network", false, "disable outbound abuse detector")
	disableDNS := fs.Bool("no-dns", false, "disable DNS anomaly / known-bad domain detector")
	disableAudit := fs.Bool("no-audit", false, "disable audit.log detector")
	disableRootkit := fs.Bool("no-rootkit", false, "disable rootkit checks")
	disableFIM := fs.Bool("no-fim", false, "disable file integrity detector")
	disableRansomware := fs.Bool("no-ransomware", false, "disable ransomware home-directory detector")
	disableServiceLogs := fs.Bool("no-service-logs", false, "disable mail/web/control-panel log detectors")
	disableCorrelator := fs.Bool("no-correlator", false, "disable brute-force / first-seen correlation")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vpsguard: %v\n", err)
		os.Exit(1)
	}
	if *authLogOverride != "" {
		cfg.AuthLog = *authLogOverride
	}

	var detectors []detector.Detector
	if !*disableSSH && cfg.AuthLog != "" {
		detectors = append(detectors, &ssh.Detector{Source: cfg.AuthLog})
	}
	if !*disableProcess {
		detectors = append(detectors, &process.Detector{})
	}
	if !*disableCPU {
		detectors = append(detectors, &cpu.Detector{
			Threshold:      cfg.CPU.Threshold,
			SustainSeconds: cfg.CPU.SustainSeconds,
		})
	}
	if !*disableFilewatch && runtime.GOOS == "linux" {
		detectors = append(detectors, &filewatch.Detector{})
	}
	if !*disableNetwork && runtime.GOOS == "linux" {
		detectors = append(detectors, &network.Detector{KnownBadIPs: cfg.KnownBadPrefixes()})
	}
	if !*disableDNS && runtime.GOOS == "linux" {
		detectors = append(detectors, &dns.Detector{KnownBadDomains: cfg.KnownBadDomainList()})
	}
	if !*disableAudit && runtime.GOOS == "linux" {
		detectors = append(detectors, &audit.Detector{})
	}
	if !*disableRootkit && runtime.GOOS == "linux" {
		detectors = append(detectors, &rootkit.Detector{})
	}
	if !*disableFIM && runtime.GOOS == "linux" {
		detectors = append(detectors, &fim.Detector{StatePath: filepath.Join(cfg.StateDir, "fim.db")})
	}
	if !*disableRansomware && runtime.GOOS == "linux" {
		detectors = append(detectors, &ransomware.Detector{})
	}
	if !*disableServiceLogs {
		for _, d := range logpattern.DefaultDetectors() {
			det := d
			detectors = append(detectors, det)
		}
	}
	if !*disableSelfhash {
		detectors = append(detectors, &selfhash.Detector{})
	}
	if !*disableHeartbeat {
		detectors = append(detectors, &heartbeat.Detector{})
	}

	if len(detectors) == 0 {
		fmt.Fprintln(os.Stderr, "vpsguard: no detectors enabled")
		os.Exit(2)
	}

	sinks := []agent.Sink{agent.NewStdoutSink(os.Stdout)}
	if !*disableTelegram && cfg.Telegram.Configured() {
		sender := &telegram.Sender{
			BotToken: cfg.Telegram.BotToken,
			ChatID:   cfg.Telegram.ChatID,
		}
		sinks = append(sinks, agent.NewTelegramSink(sender, cfg.MinSeverity))
		fmt.Fprintf(os.Stderr, "vpsguard: Telegram sink enabled (min severity=%s)\n", cfg.MinSeverity)
	} else {
		fmt.Fprintln(os.Stderr, "vpsguard: Telegram not configured (stdout only)")
	}

	var bg []agent.BackgroundRunner
	if cfg.HealthcheckURL != "" {
		bg = append(bg, &heartbeat.Pinger{URL: cfg.HealthcheckURL})
		fmt.Fprintln(os.Stderr, "vpsguard: healthchecks.io pings enabled")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var corr agent.Correlator
	if !*disableCorrelator {
		known, err := correlate.NewFileKnownIPs(filepath.Join(cfg.StateDir, "known_ips.json"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "vpsguard: known IPs persistence disabled: %v\n", err)
			known, _ = correlate.NewFileKnownIPs("") // in-memory fallback
		}
		corr = correlate.New(cfg, known)
	}

	a := &agent.Agent{
		Server:     cfg.ServerName,
		Detectors:  detectors,
		Sinks:      sinks,
		Correlator: corr,
		Background: bg,
	}
	if err := a.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "vpsguard: %v\n", err)
		os.Exit(1)
	}
}

// testAlertCmd sends a synthetic alert to the configured Telegram chat
// and exits with status 0 on success. Used during install to verify the
// user pasted their bot token + chat ID correctly.
func testAlertCmd(args []string) {
	fs := flag.NewFlagSet("test-alert", flag.ExitOnError)
	configPath := fs.String("config", config.DefaultPath, "path to config.yml")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ load config: %v\n", err)
		os.Exit(1)
	}
	if !cfg.Telegram.Configured() {
		fmt.Fprintln(os.Stderr, "✗ Telegram is not configured. Set telegram.bot_token and telegram.chat_id in", *configPath)
		os.Exit(1)
	}

	sender := &telegram.Sender{
		BotToken: cfg.Telegram.BotToken,
		ChatID:   cfg.Telegram.ChatID,
	}
	sink := agent.NewTelegramSink(sender, event.SevInfo) // override min so the test always fires

	synthetic := event.New(event.TypeAgentStarted, event.SevHigh,
		"vpsguard test alert").
		WithSource("test-alert").
		WithMessage("If you can read this, vpsguard can reach your Telegram chat.").
		WithField("server", cfg.ServerName)
	synthetic.Server = cfg.ServerName
	synthetic.Time = time.Now().UTC()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := sink.Send(ctx, synthetic); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Telegram send failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "✓ Test alert sent to chat %s\n", cfg.Telegram.ChatID)
}
