# vpsguard

> Know the moment your VPS gets hacked.

vpsguard is a single-binary Linux agent that detects suspicious activity on your VPS and (in v0.2+) sends instant Telegram alerts.

It watches for: SSH brute-force, new SSH logins, crypto miners, CPU spikes, suspicious processes, new cron jobs, new SSH keys, new users, sudoer changes, systemd changes, and agent tampering.

**Open source. VPS-only. No dashboard required. No hosted backend. Free. MIT licensed.**

## Status

Pre-alpha — `v0.1` (local prototype, JSONL stdout). See [`docs/ROADMAP.md`](docs/ROADMAP.md) for what's coming.

## Build from source

Requires Go 1.24+.

```bash
git clone https://github.com/ceorkm/vpsguard.git
cd vpsguard
go build -o vpsguard ./cmd/vpsguard
```

Cross-compile for a Linux VPS from any host:

```bash
GOOS=linux GOARCH=amd64 go build -o vpsguard-linux-amd64 ./cmd/vpsguard
```

## Run

```bash
sudo ./vpsguard run
```

The agent watches `/var/log/auth.log` and emits JSONL events to stdout. One line per event.

### CLI flags

```
vpsguard run [flags]
vpsguard install
vpsguard uninstall
vpsguard status
vpsguard logs --follow
vpsguard test-alert
vpsguard test-event --type all

  --auth-log <path>    SSH auth log to tail (default /var/log/auth.log; '-' reads stdin)
  --server <name>      label attached to every event (default: hostname)
  --no-ssh             disable SSH log detector
  --no-process         disable /proc walker
  --no-cpu             disable CPU spike detector
  --no-filewatch       disable filesystem watcher
  --no-heartbeat       disable heartbeat events
  --no-network         disable outbound abuse detector
  --no-selfhash        disable agent binary tamper detector
  --no-telegram        disable Telegram delivery
```

### Example output

```json
{"type":"agent.started","severity":"info","time":"2026-05-02T21:14:00Z","server":"main-vps","source":"heartbeat","title":"vpsguard agent started"}
{"type":"ssh.login.failed","severity":"low","time":"2026-05-02T21:14:01Z","server":"main-vps","source":"ssh","title":"SSH login failed","fields":{"ip":"185.220.101.45","user":"root"}}
{"type":"ssh.login.success","severity":"medium","time":"2026-05-02T21:14:30Z","server":"main-vps","source":"ssh","title":"SSH login (publickey)","fields":{"ip":"102.89.34.12","user":"root"}}
{"type":"process.known_miner","severity":"high","time":"2026-05-02T21:24:00Z","server":"main-vps","source":"process","title":"Possible crypto miner running","fields":{"cmdline":"/var/tmp/xmrig --donate-level 1","exe":"/var/tmp/xmrig","pid":8421}}
{"type":"cron.modified","severity":"high","time":"2026-05-02T21:25:14Z","server":"main-vps","source":"filewatch","title":"Cron drop-in directory changed","fields":{"op":"CREATE","path":"/etc/cron.d/update"}}
{"type":"outbound.rdp_spike","severity":"high","time":"2026-05-02T21:25:20Z","server":"main-vps","source":"network","title":"Possible outbound RDP brute-force from this server","fields":{"port":3389,"unique_dst_ips":25,"window":"10m0s"}}
{"type":"agent.heartbeat","severity":"info","time":"2026-05-02T21:25:30Z","server":"main-vps","source":"heartbeat","title":"agent heartbeat","fields":{"interval_seconds":30}}
```

## What each detector watches

| Detector | What it does |
|----------|--------------|
| `ssh` | Tails auth.log, regex-matches Failed/Accepted/Invalid-user/max-auth events |
| `process` | Walks `/proc` every 10s. Flags execs in `/tmp`, `/var/tmp`, `/dev/shm`, `/run/lock`. Matches process names + cmdlines against known crypto-miner list (xmrig, kinsing, kdevtmpfsi, t-rex, ...). Flags deleted binaries and sustained high-CPU processes |
| `cpu` | Reads `/proc/stat` every 5s. Fires `cpu.spike` when sustained ≥90% CPU for 5min (configurable in v0.2+) |
| `filewatch` | inotify on cron paths, sudoers, /etc/passwd, root authorized_keys, systemd unit dir, /etc/ld.so.preload, /etc/profile, /etc/bash.bashrc |
| `network` | Polls `/proc/net/tcp{,6}` for outbound SSH/SMTP/RDP spikes and mining-pool ports |
| `selfhash` | Hashes the running agent binary and emits `agent.binary_modified` if it changes after startup |
| `heartbeat` | Emits `agent.started` on launch, `agent.heartbeat` every 30s, `agent.stopped` on shutdown — feeds healthchecks.io-style silence detection in v0.2+ |

## Event taxonomy

See `internal/event/event.go` for the full constant list. The wire format is locked by `internal/event/event_test.go`; any breaking change requires updating the test deliberately.

## Troubleshooting

**No events.** Check that `/var/log/auth.log` exists (RHEL/CentOS uses `/var/log/secure` — pass `--auth-log /var/log/secure`). The agent will emit an `agent.error` event if the path is wrong. Run as root — `/proc` walks and `/var/log/auth.log` need privileges.

**inotify watcher fails on a busy server.** Bump the kernel limit:

```bash
echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

**No process detector events on macOS.** Expected — `process` and `cpu` detectors are Linux-only and stub out cleanly on darwin so the project builds on dev machines.

## Reference repos

`docs/reference-analysis.md` summarizes what vpsguard borrows (and doesn't) from Wazuh, CrowdSec, Fail2Ban, Falco, Tetragon, and the Linux audit framework. The clones live in `references/` (gitignored).

## Roadmap

[`docs/ROADMAP.md`](docs/ROADMAP.md) — full MITRE ATT&CK coverage matrix and phased plan up to v3.

## License

MIT. See [LICENSE](LICENSE).
