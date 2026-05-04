<div align="center">

# vpsguard

**Know the moment your VPS gets hacked.**

A single-binary Linux agent that watches your server and pings you on Telegram the second something looks wrong.

[![ci](https://github.com/ceorkm/vpsguard/actions/workflows/ci.yml/badge.svg)](https://github.com/ceorkm/vpsguard/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/ceorkm/vpsguard?include_prereleases&sort=semver)](https://github.com/ceorkm/vpsguard/releases)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

</div>

---

## Install

### Linux VPS

```bash
curl -fsSL https://raw.githubusercontent.com/ceorkm/vpsguard/main/packaging/install.sh | sudo bash
```

The installer downloads the latest GitHub release for your VPS architecture,
installs the systemd service, writes the default config if missing, asks for
Telegram setup when running interactively, installs local audit rules and loads
them when auditd tools are present, then starts vpsguard.

You can also install from the `.deb` or `.rpm` assets attached to GitHub
Releases.

---

## What `configure` does

```
┌──────────────────────────────────────────────────────────────┐
│  vpsguard setup — let's get your Telegram alerts wired up.  │
└──────────────────────────────────────────────────────────────┘

If you don't have a bot yet, do this in another tab first:
  1. Open Telegram, message @BotFather, send /newbot.
  2. Pick a name + username. BotFather replies with a token like
     123456789:AAH...xyz — paste that below when asked.
  3. Open your new bot and send it /start.
  4. Message @userinfobot to get your numeric chat_id.

Server label (shows on every alert) [main-vps]:
Telegram bot token: 123456789:AAHrealtoken...
Telegram chat_id (numeric): 987654321
healthchecks.io URL (optional, press Enter to skip):

Wrote config: /etc/vpsguard/config.yml (mode 0600)
Sending test alert to your Telegram chat...
✓ Test alert delivered. Open Telegram to confirm you received it.
```

---

## What you'll see on Telegram

```
🚨 New SSH login
Server: main-vps
User: root
IP: 185.220.101.45
Method: publickey
This IP has never logged into this server before.
Time: 2026-05-03 21:14 UTC
```

```
🚨 SSH brute-force attack detected
Server: main-vps
IP: 45.227.255.215
Failed attempts: 72
Distinct users: 8
Window: 5m0s
Time: 2026-05-03 21:18 UTC
```

```
🚨 Possible crypto miner detected
Server: main-vps
Process: /var/tmp/xmrig
Cmdline: /var/tmp/xmrig --donate-level 1
PID: 8421
Reason: process name matches a known crypto-miner pattern
Time: 2026-05-03 21:22 UTC
```

---

## What it watches

| Detector | Catches |
|----------|---------|
| `ssh` | SSH brute-force, invalid users, success-after-failures, first-seen IP logins, root + password logins |
| `process` | Binaries running from `/tmp`, `/var/tmp`, `/dev/shm`; crypto-miner names (xmrig, kinsing, kdevtmpfsi…); shells spawned by web servers; reverse-shell command lines; deleted-binary processes; sustained high-CPU processes |
| `cpu` | Sustained ≥ 90% CPU for 5 minutes (configurable) |
| `filewatch` | Cron files, sudoers, `/etc/passwd`, every user's `~/.ssh/authorized_keys`, systemd units, `/etc/ld.so.preload`, shell init files |
| `network` | Outbound SSH/SMTP/RDP spikes (this VPS attacking other servers), mining-pool ports, cloud-metadata access, known-bad IP contacts, bulk transfer |
| `dns` | DNS tunneling, queries to known-bad domains |
| `audit` | Setuid execve, kernel-module loads, sensitive-file reads (via auditd) |
| `rootkit` | Hidden PIDs (`kill(0)` vs `/proc`), hidden ports (`bind()` vs `ss`), hidden `/dev` files |
| `fim` | SHA256 baseline + diff for sensitive paths |
| `ransomware` | Mass-rename to ransom extensions, ransom-note creation in `/home` |
| `logpattern` | Postfix/Dovecot/nginx/Apache/HestiaCP brute-force |
| `selfhash` | vpsguard binary modified or replaced on disk |
| `heartbeat` | Agent silence (paired with healthchecks.io) catches an attacker who kills the agent |

Correlation across detectors: events from the same source within 10 min get a stable `incident_id` so Telegram messages stay coherent instead of flooding.

---

## Day-to-day commands

```bash
sudo vpsguard configure       # interactive Telegram setup
sudo vpsguard test-alert      # send a synthetic alert to your chat
sudo vpsguard test-event      # emit synthetic detector events to stdout
sudo vpsguard status          # systemd unit status
sudo vpsguard logs --follow   # live event stream
sudo vpsguard update          # download + replace binary from latest release
sudo vpsguard uninstall       # remove agent + service (keeps config with --keep-config)
```

---

## How it stays alive after an attacker kills it

vpsguard ships every event to Telegram **immediately** — by the time an attacker reads the bot token off disk, the alert is already on your phone. After that, three layers detect tampering:

- **Heartbeat** every 30 s. Pair with the [healthchecks.io](https://healthchecks.io) free tier and your phone buzzes if the agent goes silent for more than a few minutes.
- **Self-hash** of the running binary. If the file on disk changes, you get an `agent.binary_modified` alert before the next restart.
- **Watchdog systemd unit** restarts the agent if it crashes.

The bot token is just a Telegram webhook — it can't spend money, pivot to other servers, or unlock anything. Worst case an attacker reads it: rotate via `@BotFather` in 30 seconds.

---

## Configuration

Default config lives at `/etc/vpsguard/config.yml` (mode 0600, root-only). The full schema:

```yaml
server_name: main-vps
healthcheck_url: https://hc-ping.com/your-uuid
min_severity: medium                      # info | low | medium | high | critical

telegram:
  bot_token: "123456789:AAH..."
  chat_id:   "987654321"

trusted_ips:                              # successful logins from these are downgraded
  - 203.0.113.10
  - 198.51.100.0/24

known_bad_ips:                            # alert (don't block) on contact
  - 203.0.113.66
known_bad_domains:
  - malware.example

cpu:
  threshold: 90
  sustain_seconds: 300
```

---

## Roadmap

[`docs/ROADMAP.md`](docs/ROADMAP.md) tracks every detection technique mapped to its MITRE ATT&CK ID and target version. The matrix covers persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, exfiltration, and impact.

---

## Build from source

Requires Go 1.24+:

```bash
git clone https://github.com/ceorkm/vpsguard.git
cd vpsguard
go test -race ./...
go build -o vpsguard ./cmd/vpsguard
```

Cross-compile for any Linux VPS from any host:

```bash
GOOS=linux GOARCH=amd64 go build -o vpsguard-linux-amd64 ./cmd/vpsguard
GOOS=linux GOARCH=arm64 go build -o vpsguard-linux-arm64 ./cmd/vpsguard
```

---

## Documentation

- [`docs/ROADMAP.md`](docs/ROADMAP.md) — MITRE ATT&CK coverage matrix + phased plan
- [`docs/VERIFY.md`](docs/VERIFY.md) — manual verification procedure on a real Linux box
- [`docs/PRIVACY.md`](docs/PRIVACY.md) — what the agent reads, sends, and stores
- [`docs/RELEASING.md`](docs/RELEASING.md) — how to cut a release
- [`docs/reference-analysis.md`](docs/reference-analysis.md) — what we borrowed from Wazuh, CrowdSec, Fail2Ban, Falco, Tetragon, auditd

---

## License

MIT. See [LICENSE](LICENSE). No telemetry. No hosted backend. No paid tier. Built for the culture.
