package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
	"github.com/ceorkm/vpsguard/internal/notify/telegram"
)

// configureCmd is an interactive walkthrough that writes
// /etc/vpsguard/config.yml after gathering the user's Telegram bot
// token, chat ID, and a few optional fields. It exists so the install
// experience is "answer four questions, get a working agent" rather
// than "edit YAML in vim".
func configureCmd(args []string) {
	fs := flag.NewFlagSet("configure", flag.ExitOnError)
	out := fs.String("out", configPath(), "path to write the config file")
	force := fs.Bool("force", false, "overwrite existing config")
	skipTest := fs.Bool("skip-test", false, "skip sending a test Telegram alert at the end")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	if !*force {
		if info, err := os.Stat(*out); err == nil && info.Size() > 0 {
			cfgBody, _ := os.ReadFile(*out)
			if !strings.Contains(string(cfgBody), "REPLACE_WITH") {
				fmt.Fprintf(os.Stderr,
					"vpsguard: %s already exists. Re-run with --force to overwrite.\n", *out)
				os.Exit(1)
			}
		}
	}

	in := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Println("┌──────────────────────────────────────────────────────────────┐")
	fmt.Println("│  vpsguard setup — let's get your Telegram alerts wired up.  │")
	fmt.Println("└──────────────────────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("If you don't have a bot yet, do this in another tab first:")
	fmt.Println("  1. Open Telegram, message @BotFather, send /newbot.")
	fmt.Println("  2. Pick a name + username. BotFather replies with a token like")
	fmt.Println("     123456789:AAH...xyz — paste that below when asked.")
	fmt.Println("  3. Open your new bot and send it /start (otherwise it can't DM you).")
	fmt.Println("  4. Message @userinfobot to get your numeric chat_id.")
	fmt.Println()

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "main-vps"
	}
	server := promptDefault(in, "Server label (shows on every alert)", hostname)
	token := promptRequired(in, "Telegram bot token", validateTelegramToken)
	chatID := promptRequired(in, "Telegram chat_id (numeric)", validateChatID)
	healthcheck := promptDefault(in, "healthchecks.io URL (optional, press Enter to skip)", "")
	severity := promptDefault(in, "Minimum severity for Telegram (info|low|medium|high|critical)", "medium")

	body := buildConfigYAML(configValues{
		ServerName:     server,
		BotToken:       token,
		ChatID:         chatID,
		HealthcheckURL: healthcheck,
		MinSeverity:    severity,
	})

	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fatalf("configure: mkdir: %v", err)
	}
	if err := os.WriteFile(*out, []byte(body), 0o600); err != nil {
		fatalf("configure: write: %v", err)
	}
	fmt.Printf("\nWrote config: %s (mode 0600)\n", *out)

	if *skipTest {
		fmt.Println("Skipping test alert. Run `vpsguard test-alert` to verify Telegram delivery.")
		return
	}

	fmt.Println("Sending test alert to your Telegram chat...")
	if err := sendConfigureTestAlert(token, chatID, server); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Test alert failed: %v\n", err)
		fmt.Fprintln(os.Stderr, "  Double-check the bot token and chat_id, then run: vpsguard configure --force")
		os.Exit(1)
	}
	fmt.Println("✓ Test alert delivered. Open Telegram to confirm you received it.")
	fmt.Println()
	fmt.Println("Next: enable and start the service:")
	fmt.Println("  sudo systemctl enable --now vpsguard")
	fmt.Println("  sudo journalctl -u vpsguard -f")
}

func sendConfigureTestAlert(token, chatID, server string) error {
	sender := &telegram.Sender{BotToken: token, ChatID: chatID}
	ev := event.New(event.TypeAgentStarted, event.SevHigh, "vpsguard configured").
		WithSource("configure").
		WithMessage("If you can read this, vpsguard can reach your Telegram chat.")
	ev.Server = server
	ev.Time = time.Now().UTC()
	ev.WithField("server", server)

	text := "🎉 *vpsguard is configured*\n*Server:* " +
		telegram.EscapeMarkdownV2(server) +
		"\nIf you can read this, vpsguard can reach your Telegram chat\\."
	ctx, cancel := contextDeadline(30 * time.Second)
	defer cancel()
	return sender.Send(ctx, text)
}

func contextDeadline(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func promptDefault(in *bufio.Reader, label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, err := in.ReadString('\n')
	if err != nil {
		fatalf("configure: aborted")
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func promptRequired(in *bufio.Reader, label string, validate func(string) error) string {
	for {
		fmt.Printf("%s: ", label)
		line, err := in.ReadString('\n')
		if err != nil {
			fatalf("configure: aborted")
		}
		line = strings.TrimSpace(line)
		if err := validate(line); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %v\n", err)
			continue
		}
		return line
	}
}

func validateTelegramToken(v string) error {
	if v == "" {
		return fmt.Errorf("token cannot be empty")
	}
	// Telegram tokens look like 123456789:AAH...xyz — at least one colon
	// and length > 10. We don't fully validate; @BotFather is the source
	// of truth.
	if !strings.Contains(v, ":") || len(v) < 20 {
		return fmt.Errorf("doesn't look like a Telegram bot token (expected something like 123456789:AAH...)")
	}
	if strings.Contains(strings.ToUpper(v), "REPLACE") || strings.Contains(strings.ToUpper(v), "YOUR_") {
		return fmt.Errorf("looks like a placeholder, not a real token")
	}
	return nil
}

func validateChatID(v string) error {
	if v == "" {
		return fmt.Errorf("chat_id cannot be empty")
	}
	for i, r := range v {
		if i == 0 && r == '-' {
			continue // group chats are negative
		}
		if r < '0' || r > '9' {
			return fmt.Errorf("chat_id must be numeric (got %q)", v)
		}
	}
	return nil
}

type configValues struct {
	ServerName     string
	BotToken       string
	ChatID         string
	HealthcheckURL string
	MinSeverity    string
}

func buildConfigYAML(v configValues) string {
	var sb strings.Builder
	sb.WriteString("# vpsguard config — generated by `vpsguard configure`\n")
	sb.WriteString("# Edit by hand any time. Re-run `vpsguard configure --force` to regenerate.\n\n")
	fmt.Fprintf(&sb, "server_name: %q\n", v.ServerName)
	if v.MinSeverity != "" {
		fmt.Fprintf(&sb, "min_severity: %s\n", v.MinSeverity)
	}
	if v.HealthcheckURL != "" {
		fmt.Fprintf(&sb, "healthcheck_url: %q\n", v.HealthcheckURL)
	}
	sb.WriteString("\ntelegram:\n")
	fmt.Fprintf(&sb, "  bot_token: %q\n", v.BotToken)
	fmt.Fprintf(&sb, "  chat_id:   %q\n", v.ChatID)
	sb.WriteString("\n# Optional: trusted source IPs / CIDRs whose successful logins are downgraded.\n")
	sb.WriteString("# trusted_ips:\n")
	sb.WriteString("#   - 203.0.113.10\n")
	sb.WriteString("#   - 198.51.100.0/24\n\n")
	sb.WriteString("# Optional: known-bad IPs / domains. vpsguard alerts (does NOT block) on contact.\n")
	sb.WriteString("# known_bad_ips:\n")
	sb.WriteString("#   - 203.0.113.66\n")
	sb.WriteString("# known_bad_domains:\n")
	sb.WriteString("#   - malware.example\n")
	return sb.String()
}

func configPath() string {
	if v := os.Getenv("VPSGUARD_CONFIG"); v != "" {
		return v
	}
	return "/etc/vpsguard/config.yml"
}
