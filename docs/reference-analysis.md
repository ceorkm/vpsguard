# vpsguard — Reference Analysis Index

This is the consolidated synthesis of the 6 reference repos cloned in `references/`. Each gets a dedicated deep-dive file; this index summarizes what to steal, what to skip, and licensing.

| Repo | Lines | License | Verdict |
|------|-------|---------|---------|
| **fail2ban** | 4.5M | GPL v2 | Patterns only — port regex library to Go |
| **crowdsec** | 13M | **MIT** | Code & patterns — copy verbatim with attribution |
| **wazuh** | 162M | GPL v2 | Reimplement algorithms in Go to keep MIT |
| **falco** | 16M | **Apache 2.0** | Rules library — reimplement YAML logic in Go |
| **tetragon** | 232M | **Apache 2.0** | v2 reference for eBPF; not MVP |
| **audit-userspace** | 5.1M | GPL v2 / LGPL v2.1 | Required dep; ship our own rules + tail audit.log |

Detailed per-repo analyses:
- `analysis-fail2ban.md`
- `analysis-crowdsec.md`
- `analysis-wazuh.md`
- `analysis-falco.md`
- `analysis-tetragon-auditd.md`

---

## Top-Level Findings

### 1. License-driven architecture

To keep vpsguard **MIT-licensable**:
- Copy code freely from CrowdSec (MIT), Falco (Apache 2.0), Tetragon (Apache 2.0)
- Port **patterns** (regex, rule conditions, watched-paths lists) from Fail2Ban (GPL v2) and Wazuh (GPL v2) — patterns describe third-party log/file facts, not creative expression
- Reimplement **algorithms** from Wazuh (rootcheck PID/port/dev tricks) — concepts aren't copyrightable
- Use auditd as a runtime dependency (LGPL `auparse` is link-clean, but we'll just tail `/var/log/audit/audit.log` in pure Go to avoid cgo)

### 2. The Stack (Go MVP)

```
github.com/nxadm/tail        # log file tail with rotation     (CrowdSec)
github.com/fsnotify/fsnotify # inotify file watching            (CrowdSec)
golang.org/x/time/rate       # token bucket rate limiter        (CrowdSec)
github.com/crowdsecurity/grokky  # grok pattern compilation     (CrowdSec)
github.com/sirupsen/logrus   # structured logging               (CrowdSec)
gopkg.in/tomb.v2             # goroutine lifecycle              (CrowdSec)
github.com/coreos/go-systemd/v22  # journald (alt path)         (CrowdSec)
github.com/wasilibs/go-re2   # RE2 (no backtracking)            (CrowdSec)
gopkg.in/yaml.v3             # config                           (standard)
github.com/spf13/cobra       # CLI                              (standard)
go.etcd.io/bbolt             # local SQLite-alt for FIM baseline (standard)
```

### 3. The Detection Pipeline

```
Log/event source                                Detector
─────────────────                              ──────────────────────
/var/log/auth.log (tail)        ─┐
journalctl -f sshd             ─┼─→  syslog header parse  ─→ grok SSH patterns ─→ leaky bucket per IP
/var/log/audit/audit.log       ─┤
                                 │
inotify (cron, sudoers, ssh keys, ↘
  systemd, ld.so.preload)         → file integrity event ─→ severity classifier
                                 ↗
fanotify (read /etc/shadow,    ─┤
  read .ssh/id_rsa)              │
                                 │
/proc walk (every 10s):         ─┘
  - exepath in /tmp /dev/shm
  - cmdline matches miner list
  - parent chain: web → shell
  - hidden PID via kill(0)
  - dropped binary still running

/proc/net/tcp poll (every 30s):
  - outbound to mining ports
  - excessive outbound SSH/SMTP

heartbeat → healthchecks.io ping
                                       ↓
                              event normalizer
                                       ↓
                              ThreatScore engine
                              (correlate, dedup, escalate)
                                       ↓
                              Telegram bot send
```

### 4. Detection Coverage Map (MVP → v3)

| Attack technique | Detector | MVP | v1 | v2 | v3 |
|------------------|----------|-----|----|----|----|
| **SSH brute-force** | grok auth.log + leaky bucket | ✓ | | | |
| **SSH user enum** | distinct ssh_user in bucket | ✓ | | | |
| **SSH success after fails** | correlation rule | ✓ | | | |
| **SSH success from new IP** | trusted-IP set + first-seen | ✓ | | | |
| **Crypto miner — process name** | /proc cmdline scan vs coin_miners | ✓ | | | |
| **Crypto miner — CPU spike** | /proc/stat polling | ✓ | | | |
| **Crypto miner — pool ports** | /proc/net/tcp polling | ✓ | | | |
| **Suspicious /tmp /dev/shm exec** | /proc/PID/exe scan | ✓ | | | |
| **Cron created/modified** | inotify | ✓ | | | |
| **systemd unit added** | inotify | ✓ | | | |
| **New SSH key** | inotify on authorized_keys | ✓ | | | |
| **New user / sudoer** | inotify /etc/passwd /etc/sudoers | ✓ | | | |
| **/etc/ld.so.preload modified** | inotify | ✓ | | | |
| **.bashrc / .bash_profile modified** | inotify | ✓ | | | |
| **Outbound SSH/SMTP spike** | /proc/net/tcp count | ✓ | | | |
| **Agent silence** | healthchecks.io heartbeat | ✓ | | | |
| **Postfix/Dovecot brute-force** | grok mail logs | | ✓ | | |
| **nginx/apache HTTP brute-force** | grok access logs | | ✓ | | |
| **Webshell — shell from web user** | /proc parent chain | | ✓ | | |
| **/etc/shadow read** | fanotify FAN_OPEN_PERM | | ✓ | | |
| **.ssh/id_rsa read** | fanotify | | ✓ | | |
| **AWS/GCP creds read** | fanotify | | ✓ | | |
| **Hidden PID (rootkit)** | kill(0) vs /proc | | ✓ | | |
| **Hidden port (rootkit)** | bind() vs ss output | | ✓ | | |
| **Hidden /dev file** | walk /dev | | ✓ | | |
| **Promiscuous NIC** | ip link flags | | ✓ | | |
| **setuid bit set** | auditd `chmod` rule | | ✓ | | |
| **Kernel module load** | auditd `init_module` | | ✓ | | |
| **History tampering (HISTFILE=/dev/null)** | /proc/PID/environ | | ✓ | | |
| **Log tampering (write /var/log)** | inotify, exclude rsyslog | | ✓ | | |
| **shred/wipe execution** | execve match | | ✓ | | |
| **sshd_config weakness** | startup parse | | ✓ | | |
| **Full process ancestry** | Tetragon-style execve_map | | | ✓ | |
| **commit_creds privesc** | eBPF kprobe | | | ✓ | |
| **LSM file_open bypass detection** | LSM hook | | | ✓ | |
| **TCP reverse-shell correlation** | tcp_connect kprobe | | | ✓ | |
| **ptrace injection** | sys_ptrace kprobe | | | ✓ | |
| **TTY keystroke capture** | tty_write kprobe | | | ✓ | |
| **DNS tunneling** | DNS query rate analysis | | | ✓ | |
| **Inline blocking (kill process)** | Tetragon Override/Sigkill | | | | ✓ |
| **AI incident summary** | LLM over event timeline | | | | ✓ |

### 5. The Telegram Alert Library (PRD section 23 grounded in detectors)

Every alert below has a concrete detector path:

| Alert | Detector(s) | Source repo |
|-------|-------------|-------------|
| 🚨 New root login | grok `Accepted password\|publickey for root` + first-seen IP set | CrowdSec parser, Fail2Ban regex |
| 🚨 SSH brute-force | grok `Failed password` + leaky bucket per IP | CrowdSec scenario, Fail2Ban regex |
| 🚨 Possible crypto miner | /proc cmdline ∈ coin_miners ∨ exepath ∈ /tmp ∨ /proc/net/tcp port ∈ pool_ports | Falco lists, Wazuh dev/tmp checks |
| 🚨 Suspicious process | exepath ∈ /tmp ∨ /dev/shm ∨ web-user-spawned-shell | Falco rules |
| 🚨 New cron job | inotify on /etc/cron* + /var/spool/cron | Wazuh syscheck, Falco rule |
| 🚨 New SSH key | inotify on authorized_keys | Wazuh syscheck, auditd watches |
| 🚨 New sudo user | inotify on /etc/sudoers + /etc/passwd | Wazuh syscheck, auditd |
| 🚨 New systemd service | inotify on /etc/systemd/system/ | Falco rule |
| 🚨 Outbound brute-force | /proc/net/tcp connection count to many IPs:22 | (built from scratch) |
| 🚨 Agent offline | healthchecks.io watchdog | (architectural) |

---

## What We Will NOT Take from References

- **Wazuh manager/agent protocol** — vpsguard is single-binary, no manager
- **CrowdSec central API + bouncers** — no SaaS layer
- **Falco containers/k8s rules** — VPS focus, not container
- **Tetragon eBPF for MVP** — kernel version requirement too strict
- **auparse cgo dependency** — pure Go via log tail
- **Fail2Ban iptables actions** — alert-only, no auto-block

---

## Files Index

```
docs/
  reference-analysis.md       (this file)
  analysis-fail2ban.md
  analysis-crowdsec.md
  analysis-wazuh.md
  analysis-falco.md
  analysis-tetragon-auditd.md
  ROADMAP.md                  (next)
```
