# vpsguard Roadmap

> **North star:** No matter who the hacker is, if they get into ANY VPS, vpsguard catches them immediately and your phone buzzes on Telegram.

The promise is simple. The implementation is layered: each phase closes more attacker exit doors. By v3 there is no realistic post-compromise behavior on a Linux VPS that vpsguard misses within seconds.

---

## A. Detection Coverage Matrix (MITRE ATT&CK aligned)

Status legend: `M`=MVP (v0.3), `1`=v1.x, `2`=v2.x, `F`=Future

### Initial Access (TA0001)

| Technique | ID | Detector | Phase |
|-----------|----|----------|-------|
| SSH brute-force | T1110.001 | grok auth.log + leaky bucket | M |
| SSH password spray (many users, few attempts) | T1110.003 | distinct ssh_user count per IP | M |
| SSH compromised credentials (success after fails) | T1078 | correlation: failed-burst → success | M |
| Exposed control panel brute-force (HestiaCP, cPanel, aaPanel) | T1190 | grok panel logs | 1 |
| Web app exploit landing in /tmp | T1190 | inotify /tmp + close_write + exec | 1 |
| Postfix/Dovecot SMTP/IMAP brute-force | T1110.001 | grok mail logs (Fail2Ban patterns) | 1 |
| MySQL/Postgres auth brute-force | T1110.001 | grok mysql/postgres logs | 1 |
| FTP/SFTP brute-force | T1110.001 | grok proftpd/vsftpd logs | 1 |
| Stolen SSH private key reuse | T1078 | first-seen-IP analysis on success login | 1 |

### Execution (TA0002)

| Technique | ID | Detector | Phase |
|-----------|----|----------|-------|
| Shell from web server (nginx/php/apache → bash) | T1059.004 | /proc parent-chain walk | 1 |
| Shell from interpreter (python/perl/ruby → bash) | T1059.004 | parent-chain | 1 |
| Execution from /tmp | T1059 | /proc/PID/exe prefix check | M |
| Execution from /dev/shm | T1059, T1620 | /proc/PID/exe prefix check | M |
| Fileless (deleted binary still running) | T1620 | /proc/*/exe → "(deleted)" suffix | 1 |
| Reflective ELF loading | T1620 | /proc/PID/maps anonymous executable mapping | 2 |
| netcat with `-e`/`-c` (RCE) | T1059.004 | execve args inspection | M |
| `bash -i >& /dev/tcp/...` reverse shell | T1059.004 | dup2 syscall to socket fd (eBPF) | 2 |
| Container escape via release_agent | T1611 | inotify on cgroup release_agent | 2 |

### Persistence (TA0003)

| Technique | ID | Detector | Phase |
|-----------|----|----------|-------|
| New cron job (`/etc/cron.d/`, `/etc/crontab`, `/var/spool/cron/`) | T1053.003 | inotify | M |
| User crontab modified | T1053.003 | inotify `/var/spool/cron/crontabs/` | M |
| New systemd service (`/etc/systemd/system/*.service`) | T1543.002 | inotify | M |
| New systemd timer | T1053.006 | inotify | 1 |
| New SSH authorized key | T1098.004 | inotify on `authorized_keys` (root + /home/*) | M |
| Authorized key with `command=` forced | T1098.004 | content scan on key file changes | 1 |
| New Linux user | T1136.001 | inotify on /etc/passwd | M |
| New sudoer | T1078.003 | inotify on /etc/sudoers + /etc/sudoers.d/ | M |
| User added to wheel/sudo/docker group | T1098 | inotify /etc/group + execve `usermod -aG` | 1 |
| `/etc/ld.so.preload` modified (linker rootkit) | T1574.006 | inotify | M |
| `~/.bashrc` / `/etc/profile` / `/etc/bash.bashrc` modified | T1546.004 | inotify | M |
| `/etc/motd` / `/etc/update-motd.d/` modified | T1546.004 | inotify | 1 |
| PAM module added or modified | T1556.003 | inotify on /etc/pam.d/ + /lib/security/ | 1 |
| `/etc/rc.local` modified | T1037.004 | inotify | 1 |
| systemd-run scheduled task | T1053.006 | auditd `setup_systemd_run` rule | 1 |
| Web shell file created in webroot | T1505.003 | optional path-watch (user-configured webroots) | 1 |
| Kernel module loaded | T1547.006 | auditd `init_module`/`finit_module` syscall | 1 |
| Unsigned kernel module loaded | T1547.006 | eBPF `security_kernel_read_file` LSM | 2 |

### Privilege Escalation (TA0004)

| Technique | ID | Detector | Phase |
|-----------|----|----------|-------|
| Setuid bit added to binary | T1548.001 | auditd `chmod` rule with mode mask | 1 |
| Setuid execve (uid != euid) | T1548.001 | auditd setuid-exec key | 1 |
| `commit_creds()` to root from non-root | T1068 | eBPF kprobe | 2 |
| Sudo abuse (NOPASSWD enumeration) | T1548.003 | execve `sudo -l` repeated | 1 |
| Capability gain (`cap_capable` checks) | T1068 | eBPF kprobe | 2 |
| Kernel exploit (sudden privesc with no setuid call) | T1068 | eBPF commit_creds (only catches via kernel layer) | 2 |
| Polkit / pkexec abuse (PwnKit-style) | T1068 | execve pkexec arg pattern | 1 |

### Defense Evasion (TA0005)

| Technique | ID | Detector | Phase |
|-----------|----|----------|-------|
| `HISTFILE=/dev/null` / `HISTSIZE=0` in env | T1562.003 | /proc/PID/environ on new procs | 1 |
| `unset HISTFILE` in shell | T1562.003 | execve scan + bash audit hook | 1 |
| `history -c` execution | T1562.003 | shell builtin via auditd execve | 1 |
| `shred`/`wipe`/`scrub` executed | T1070.004 | execve match data_remove_binaries | 1 |
| Direct write to /var/log files | T1070.002 | inotify, allowlist rsyslog/journald/process | 1 |
| Log file truncated (rsyslog not the writer) | T1070.002 | size decrease detection | 1 |
| `auditctl -e 0` (audit disable) | T1562.001 | auditd config-change watch | 1 |
| systemd unit stopped (vpsguard, auditd, rsyslog) | T1489 | service unit state poll | M |
| vpsguard agent killed | T1489 | healthchecks.io heartbeat silence | M |
| vpsguard binary modified or replaced | T1554 | self-hash on startup + periodic | 1 |
| Hidden process (rootkit) | T1014 | kill(0) vs /proc cross-check | 1 |
| Hidden port (rootkit) | T1014 | bind() vs ss/netstat cross-check | 1 |
| Hidden file (link-count vs readdir) | T1014 | dir stat vs readdir count | 1 |
| Hidden /dev regular file | T1014 | walk /dev for S_ISREG | 1 |
| Promiscuous NIC | T1040 | ip link flag check | 1 |
| Process running deleted binary | T1620 | /proc/*/exe → "(deleted)" | 1 |
| LD_PRELOAD env injection | T1574.006 | /proc/PID/environ scan | 1 |
| chattr +i to lock attacker files | T1222.002 | execve `chattr` watch | 1 |

### Credential Access (TA0006)

| Technique | ID | Detector | Phase |
|-----------|----|----------|-------|
| `/etc/shadow` read by non-allowed proc | T1003.008 | fanotify FAN_OPEN_PERM | 1 |
| `/etc/passwd` read for enumeration | T1003.008 | optional fanotify | 1 |
| `~/.ssh/id_rsa` (private key) read | T1552.004 | fanotify | 1 |
| `~/.aws/credentials` / `.config/gcloud/` read | T1552.001 | fanotify | 1 |
| `~/.docker/config.json` read | T1552.001 | fanotify | 1 |
| Memory dump via `/proc/*/maps` + read | T1003.007 | fanotify on `/proc/*/mem` | 2 |
| Kernel keyring read (`keyctl`) | T1552.007 | execve `keyctl` watch | 2 |
| Shell history read by another user | T1552.003 | fanotify on `~/.bash_history` | 2 |

### Discovery (TA0007)

| Technique | ID | Detector | Phase |
|-----------|----|----------|-------|
| Network tools executed (nmap, nc, masscan, socat) | T1046 | execve match network_tool_binaries | M |
| `whoami` / `id` / `hostname` / `uname -a` burst | T1082 | execve recon-burst counter | 1 |
| `crontab -l` recon | T1083 | execve | 1 |
| `find` for setuid/world-writable | T1083 | execve args inspection | 1 |
| `cat /etc/passwd` style enumeration | T1087.001 | fanotify (optional, noisy) | F |
| `ifconfig`/`ip a`/`netstat -tulnp` recon burst | T1018 | execve burst | 1 |

### Lateral Movement (TA0008)

| Technique | ID | Detector | Phase |
|-----------|----|----------|-------|
| Outbound SSH to many hosts (this VPS attacking others) | T1021.004 | /proc/net/tcp count to port 22 | M |
| Outbound SMB (port 445/139) | T1021.002 | /proc/net/tcp | 1 |
| Outbound SMTP spike (spam relay) | T1071 | /proc/net/tcp port 25/465/587 | M |
| Outbound RDP attempts (port 3389) | T1021.001 | /proc/net/tcp | 1 |
| SSH key copy via scp/sftp from this box | T1021.004 | execve scp/sftp + auth_log | 1 |

### Collection (TA0009)

| Technique | ID | Detector | Phase |
|-----------|----|----------|-------|
| Database dump (mysqldump, pg_dump) by unusual user | T1005 | execve | 1 |
| Bulk file read (large unusual paths) | T1005 | fanotify volume tracking | 2 |
| `tar` of /home or /var on a webserver | T1560.001 | execve args inspection | 1 |

### Exfiltration (TA0010)

| Technique | ID | Detector | Phase |
|-----------|----|----------|-------|
| Bulk outbound transfer (>X MB to single IP in window) | T1041 | /proc/net/dev rate + dst pinning | 1 |
| Outbound to known sinkhole/paste sites (pastebin, transfer.sh, anonfiles, gofile) | T1567.002 | DNS query log if available | 1 |
| Outbound to file.io / 0x0.st / catbox.moe (anonymous file hosts) | T1567.002 | DNS + URL match | 1 |
| DNS tunneling (long subdomain queries, high freq) | T1071.004 | journald systemd-resolved + freq analysis | 2 |
| Cloud metadata (`169.254.169.254`) read by web user | T1552.005 | /proc/net/tcp dst | 1 |

### Impact (TA0040)

| Technique | ID | Detector | Phase |
|-----------|----|----------|-------|
| Crypto miner — process name (xmrig, kinsing, kdevtmpfsi, t-rex) | T1496 | /proc cmdline scan | M |
| Crypto miner — sustained high CPU | T1496 | /proc/stat 5-min average | M |
| Crypto miner — outbound to mining pool (3333/4444/5555/7777/14444) | T1496 | /proc/net/tcp | M |
| Crypto miner — stratum protocol detection | T1496 | TCP payload sniff (eBPF) | 2 |
| DDoS bot — outbound packet flood | T1498 | /proc/net/dev tx rate | 1 |
| DDoS bot — connection-flood pattern | T1498 | /proc/net/tcp count | 1 |
| Ransomware encryption — bulk file rename .enc/.locked | T1486 | inotify rate on /home + extension match | 2 |
| Ransomware ransom note created | T1486 | inotify match `README*.txt` / `HOW_TO_DECRYPT*` | 2 |
| Wiper — /etc/shadow zeroed | T1485 | inotify size-decrease | 1 |
| `rm -rf /` style mass deletion | T1485 | inotify delete-rate spike | 2 |

---

## B. Phased Roadmap

### v0.1 — Local agent prototype (Phase 1) — 1 week

**Goal:** Detect events locally, print JSON to stdout. No network, no notification, no config.

Features:
- [x] Read `/var/log/auth.log` (or `/var/log/secure`) with `nxadm/tail`
- [x] Grok SSH success / failure / invalid-user (CrowdSec patterns)
- [x] CPU spike detection from `/proc/stat`
- [x] Suspicious process detection: `/proc/PID/exe` startswith `/tmp` or `/dev/shm`
- [x] inotify on `/etc/cron.d/` and `/etc/cron.hourly/`
- [x] Heartbeat tick every 30s
- [x] Output: structured JSON events to stdout

Success: run as root on a test VPS, get JSON events on stdout while another shell brute-forces it.

### v0.2 — Telegram delivery (Phase 2) — 1 week

**Goal:** Real Telegram alerts. Add config file. Add healthchecks.io heartbeat.

Features:
- [x] Read `/etc/vpsguard/config.yml` (telegram_bot_token, chat_id, server_name, healthcheck_url)
- [x] HTTP POST to `https://api.telegram.org/bot<TOKEN>/sendMessage` with formatted markdown
- [x] Plain-English alert templating per PRD section 23
- [x] Optional healthchecks.io-style ping every 60s if URL configured
- [x] systemd service unit with hardening
- [x] Graceful shutdown via context/signal handling
- [x] Test alert command: `vpsguard test-alert`

Success: install on a test VPS, run `ssh root@vps` from a new IP, get a Telegram message within 5 seconds.

### v0.3 — Full PRD MVP (Phase 3) — 2-3 weeks

**Goal:** Everything in PRD section 10.

Features:
- [x] Brute-force detection via sliding windows per IP
- [x] User enumeration scenario (distinct usernames)
- [x] Success-after-failures correlation
- [x] Crypto-miner detection: process name + CPU + suspicious path + outbound port
- [x] inotify watches: `/etc/cron*`, `/var/spool/cron/`, all `authorized_keys`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/`, `/etc/systemd/system/`, `/etc/ld.so.preload`, `~/.bashrc` files
- [x] Outbound abuse: `/proc/net/tcp` polling for SSH/SMTP/RDP spikes
- [x] Trusted-IP allowlist (config file)
- [x] Severity classification (low/medium/high/critical)
- [x] Incident grouping (events within 10min window from same actor)
- [x] First-seen IP tracking via local JSON state file
- [x] Self-hash check on startup + periodic tamper check
- [x] Test mode with synthetic events
- [x] CLI: `vpsguard install|uninstall|status|logs|test-alert|test-event|version`

Success: against the founder's actual incident timeline, vpsguard fires every alert that should have fired.

### v1.0 — Hardened release — 2 weeks

**Goal:** Public release on GitHub.

Features:
- [x] Signed binaries/checksums workflow (cosign keyless bundle for checksums)
- [x] `.deb` and `.rpm` packages via `nfpm` config
- [x] One-line install script: `curl -sSL https://github.com/.../install.sh | sudo bash`
- [x] systemd hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp`, `RestrictNamespaces`, `LockPersonality`, `MemoryDenyWriteExecute`, `RestrictRealtime`
- [x] Watchdog service (systemd companion restarts main agent if killed)
- [x] Uninstall command: `vpsguard uninstall` removes service/binary/config by default
- [x] Auto-update opt-in (download release binary, replace, restart)
- [x] Public privacy/data policy
- [x] LICENSE: MIT
- [x] CI: GitHub Actions matrix (Ubuntu 20/22/24, Debian 11/12, Rocky 8/9)

### v1.1 — Webshell + control panel coverage — 2 weeks

Features:
- [x] Parent-chain detection: shell spawned by nginx/apache/php-fpm
- [x] HestiaCP / CyberPanel / aaPanel log integration
- [x] Postfix/Dovecot brute-force (Fail2Ban patterns ported)
- [x] nginx/apache HTTP brute-force (Fail2Ban patterns)
- [x] Recidive tier (repeat-offender escalation through suppressing/grouped repeat alerts)

### v1.2 — auditd integration — 2 weeks

Features:
- [x] Drop `/etc/audit/rules.d/80-vpsguard.rules` on install
- [x] Tail `/var/log/audit/audit.log` in pure Go
- [x] Setuid execve detection
- [x] Kernel module load detection
- [x] Sensitive-file access via auditd (alternative path to fanotify)

### v1.3 — Rootkit checks — 2 weeks

Features (from Wazuh rootcheck, ported to Go):
- [x] Hidden PID (kill(0) vs /proc)
- [x] Hidden port (proc listen sockets vs ss)
- [x] Hidden /dev file (walk for S_ISREG)
- [x] Dir link-count vs readdir count
- [x] File size vs stat mismatch
- [x] Promiscuous NIC
- [x] Periodic scan (every 6h, configurable)

### v1.4 — File Integrity Monitoring (FIM) — 2 weeks

Features:
- [x] Baseline SHA256 + stat for sensitive paths (Wazuh subset)
- [x] inotify realtime + 12h scheduled scan
- [x] bbolt DB for baseline storage
- [x] Diff alerts: added / deleted / modified with before/after metadata
- [x] sshd_config hardening check at startup (Wazuh SCA logic)

### v1.5 — Credential access detection — 2 weeks

Features:
- [x] auditd sensitive-file access on `/etc/shadow`, `~/.ssh/id_*`, `~/.aws/`, `~/.docker/`
- [x] LD_PRELOAD env injection detection
- [x] HISTFILE tampering detection

### v2.0 — eBPF runtime detection — 4-6 weeks

**Goal:** What audit and inotify can't catch.

Features:
- [ ] eBPF detection at runtime, fall back to userspace if kernel < 5.8 / no BTF
- [x] Userspace process ancestry fallback
- [x] auditd sensitive file_open fallback
- [ ] `commit_creds` kprobe for kernel-exploit privesc
- [ ] `cap_capable` for capability tracking
- [x] userspace reverse shell command correlation
- [x] auditd `ptrace` fallback
- [x] auditd module-load fallback
- [ ] `tty_write` for keystroke capture (forensic mode)
- [ ] Use `cilium/ebpf` Go library

### v2.1 — Network flow analysis — 2 weeks

Features:
- [x] Bulk-transfer detection (rate over window)
- [x] Outbound to configured known-bad IP/domain sets
- [x] DNS tunneling detection (long-subdomain rate)
- [x] Cloud metadata access (169.254.169.254) detection

### v2.2 — Ransomware / wiper detection — 2 weeks

Features:
- [x] inotify rate spike on /home + extension match
- [x] Mass-rename detection (`.enc`, `.locked`, `.crypto`, `.ryk`, etc.)
- [x] Ransom-note file pattern match
- [x] Mass-delete detection

### v3.0 — Response Integrations, Not Blocking

**Goal:** Stay monitor-and-alert only. vpsguard should explain what happened
and, where useful, show a suggested Fail2Ban/nftables action for the operator
to run manually or manage in Fail2Ban. It must not become a blocker.

Features:
- [x] Suggested Fail2Ban status/runbook text in alerts
- [x] Firewall guidance stays text-only; vpsguard executes no firewall commands
- [x] Telegram acknowledgement buttons for alert workflow only
- [x] No process kill, file quarantine, user lock, or automatic IP blocking

### Future / community ideas

- Local incident export/report command — read-only summary from recent events
- Multi-server view (one instance polls others' health endpoints)
- AI-generated incident summary (run llama.cpp locally, no API)
- Optional local web UI is out of MVP; CLI and alerts remain primary
- Wazuh-rule importer (read XML, translate to vpsguard rules)
- VirusTotal / AbuseIPDB enrichment on alerts (opt-in, requires their API key)
- Mobile app (Telegram replacement for users who hate Telegram)
- Compliance reports (PCI-DSS, CIS) using Wazuh SCA logic
- IPv6 full coverage parity
- Windows agent (NOT planned for this product — VPS focus is Linux)

---

## C. Prioritized Feature List with Rationale

### Tier 0 — Must ship in MVP (without these, the product fails)

1. **SSH brute-force detection** — Single most common attack on a VPS. Without this we ship nothing.
2. **Crypto-miner detection** — The founder's actual incident. Three signals (cmdline match, CPU spike, miner port) AND'd together = near-zero false positives.
3. **One-command install** — If install takes more than 60 seconds, indie hackers won't try it. Period.
4. **Telegram delivery in plain English** — Telegram is Tier-1 because most VPS owners already have it on their phone, set up takes 60 seconds, no template approval pain.
5. **inotify on cron + ssh keys + sudoers + systemd** — These are the top-4 persistence vectors. Catching ANY of them after compromise = caught.
6. **Heartbeat via healthchecks.io** — Detects agent kill / VPS down. Without this an attacker just kills vpsguard and the user thinks "all good."
7. **Outbound SSH/SMTP abuse detection** — The founder's incident was discovered by an external abuse report. We MUST be the one to tell the user first.

### Tier 1 — Closes the next class of attacks (v1.x)

8. **Webshell detection** — Every cheap VPS hosting WordPress is at risk. nginx/php-fpm spawning bash = caught.
9. **Mail-server brute-force** — VPS owners running Postfix/Dovecot get hammered. Fail2Ban patterns are mature, port them.
10. **Recidive / repeat-offender escalation** — Reduces alert fatigue. Same IP keeps trying = one summary alert, not 50.
11. **Rootkit checks** — Wazuh's hidden-PID/hidden-port logic in Go is < 100 lines per check, near-zero false positives, catches advanced attackers.
12. **FIM with SHA256 baseline** — Catches binary replacement (e.g., trojanized `ls`).
13. **fanotify on `/etc/shadow` and SSH keys** — Detects credential harvesting before exfiltration.
14. **auditd integration** — Catches setuid bit + kernel module load (these can't be caught reliably any other way without eBPF).

### Tier 2 — eBPF era (v2)

15. **Full process ancestry on every alert** — Tetragon-pattern. Every Telegram message shows the kill chain. Massively improves user trust.
16. **`commit_creds` privesc detection** — Only catches kernel-exploit privesc. Userspace can't see this.
17. **Network flow analysis** — DNS tunneling, bulk exfil, cloud-metadata access.
18. **Ransomware detection** — Inotify rate spike + extension/note match.

### Tier 3 — Response Guidance (v3)

19. **Response guidance** — vpsguard can suggest what to check or what Fail2Ban rule may apply, but it does not block, kill, quarantine, or lock accounts.

---

## D. What We Will NEVER Do

- **No SaaS / hosted backend.** The product is OSS, install on your own VPS, point at your own Telegram bot. No accounts, no central database, no telemetry leaving the user's box (except Telegram messages and optional healthchecks.io pings, both user-controlled).
- **No remote shell / no agent receives commands.** vpsguard is a VPS-local agent and does not accept remote commands.
- **No blocking or destructive response.** Fail2Ban handles blocking. vpsguard monitors, correlates, and alerts.
- **No vendor lock-in.** Use open formats: YAML config, JSON events, Markdown alerts, Telegram (interchangeable with Discord/Matrix later).
- **No Windows / macOS agent.** Linux VPS is the target. Period.
- **No Kubernetes / container security.** Out of scope. There are 10 better tools for that.
- **No full SIEM.** No correlation across machines (until users specifically ask for v3 multi-server). No 90-day retention. Local DB is small and short-lived.
- **No EDR / antivirus replacement.** No signature scanning of every file. No cloud lookup of every binary. We detect *behavior*, not *files*.
- **No paid tier in MVP.** OSS, self-host, free forever. The product direction is a VPS-local agent, not a hosted dashboard.
- **No AI-generated detection rules.** Rules are deterministic, auditable YAML. AI is reserved for incident summaries (read-only) only, and only running locally.
- **No telemetry of user data.** vpsguard never phones home. Period.

---

## E. Success Metric — The North Star Test

> "If I rerun the founder's incident timeline through vpsguard, does every silent failure become a Telegram alert?"

| Founder incident step | vpsguard detector | Phase |
|----------------------|-------------------|-------|
| Attacker SSH'd in (success from new IP) | grok auth.log + first-seen | M |
| Attacker added SSH key (persistence) | inotify on authorized_keys | M |
| Attacker added cron job (persistence) | inotify on /etc/cron.d/ | M |
| Attacker installed xmrig in /var/tmp | /proc cmdline match + exepath in /tmp | M |
| CPU climbed to 97% from miner | /proc/stat 5-min sustained | M |
| VPS started attacking other servers | /proc/net/tcp outbound count | M |
| Attacker killed agent | healthchecks.io silent | M |

All seven detections in MVP. The product passes the north-star test from day one.

What v1+ adds: parallel coverage of the next 50 attack patterns the founder hasn't personally encountered yet — but next week, somewhere in the world, another indie hacker will. vpsguard catches them all.
