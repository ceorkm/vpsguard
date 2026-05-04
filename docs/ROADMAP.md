# vpsguard Roadmap

> **North star:** if an attacker gets into a normal Linux VPS, vpsguard should
> turn the quiet compromise into a fast Telegram alert.

This roadmap is intentionally scoped to the product vpsguard is today:

- Linux VPS only
- monitor, correlate, and alert only
- no dashboard, hosted backend, signup, central database, or SaaS layer
- no firewall blocking, process killing, quarantine, or account locking
- install from the raw installer or GitHub Release assets

Official distro repository publishing and kernel eBPF work are not part of the
active roadmap. They can be revisited later, but they are not required for the
open-source VPS agent to be real and useful.

---

## Current Release Scope

### Install And Release

- [x] One-line raw installer for Linux VPS hosts
- [x] GitHub Release binaries for linux/amd64 and linux/arm64
- [x] `.deb` and `.rpm` package assets via nfpm
- [x] SHA256 checksum file
- [x] cosign keyless bundle for checksums
- [x] systemd service with hardening
- [x] watchdog companion service
- [x] auditd rule file installed by package/raw installer
- [x] interactive `vpsguard configure`
- [x] `configure` restarts the installed service so new config is active
- [x] uninstall command
- [x] update command for GitHub Release binaries

### Alert Delivery

- [x] Telegram alert delivery
- [x] MarkdownV2-safe formatting
- [x] severity gate for noisy events
- [x] `agent.error` bypasses severity gate so broken monitoring alerts the user
- [x] optional healthchecks.io heartbeat
- [x] stdout JSONL sink for local logs/testing
- [x] no fake Telegram acknowledgement buttons or callback workflow

### SSH And Login Abuse

- [x] SSH successful login detection
- [x] SSH failed login detection
- [x] invalid-user/user-enumeration detection
- [x] brute-force sliding windows per IP
- [x] password spray detection across usernames
- [x] success-after-failures correlation
- [x] first-seen IP tracking
- [x] trusted IP allowlist/downgrade

### Persistence

- [x] cron directory monitoring
- [x] user crontab monitoring
- [x] authorized_keys monitoring for root and home users
- [x] new Linux user detection
- [x] sudoers/sudoers.d monitoring
- [x] systemd service monitoring
- [x] shell init file monitoring
- [x] `/etc/ld.so.preload` monitoring
- [x] PAM config monitoring
- [x] apt hook config monitoring

### Process And Malware Behavior

- [x] suspicious process paths under `/tmp` and `/dev/shm`
- [x] deleted-binary process detection
- [x] known miner process names
- [x] sustained high CPU process detection
- [x] web server/interpreter spawning shell detection
- [x] webshell process pattern detection
- [x] `curl|sh`, `wget|bash`, and encoded shell payload detection
- [x] reverse-shell command correlation
- [x] Tor/onion downloader command detection
- [x] suspicious Docker host access command detection
- [x] clipboard tool execution detection
- [x] LD_PRELOAD environment injection detection
- [x] HISTFILE/history tampering detection
- [x] recon/network tool execution detection

### Network And DNS Abuse

- [x] outbound SSH spike detection
- [x] outbound SMTP spike detection
- [x] outbound RDP spike detection
- [x] miner pool port detection
- [x] process in temp path with outbound connection
- [x] bulk outbound transfer detection
- [x] cloud metadata access detection
- [x] known-bad IP matching from configured feeds
- [x] known-bad domain matching from configured feeds
- [x] DNS tunneling heuristic
- [x] risky public service exposure scan for Docker API, Redis, Postgres,
      MySQL, MongoDB, Elasticsearch, WebLogic, Jenkins/dev HTTP, Jupyter,
      Kubernetes API/kubelet, VNC, and Memcached

### File Integrity And Audit

- [x] FIM SHA256/stat baseline for sensitive paths
- [x] bbolt-backed FIM baseline persistence
- [x] immediate FIM check on startup
- [x] scheduled FIM scan
- [x] realtime filewatch events where supported
- [x] sshd_config hardening checks
- [x] audit.log parser in pure Go
- [x] setuid chmod audit detection
- [x] kernel module load audit detection
- [x] ptrace audit detection
- [x] sensitive-file audit detection
- [x] PAM audit detection for `/etc/pam.d`

### Credential Access

- [x] `/etc/shadow` access signal via audit/log parsing where available
- [x] process FD scan for SSH private keys
- [x] process FD scan for AWS, Docker, kubeconfig, npm, PyPI, GitHub, git, and
      shell-history credentials
- [x] `/dev/input` and `/dev/uinput` FD scan as keylogger clues

### Rootkit, Ransomware, And Tamper Signals

- [x] hidden PID check
- [x] hidden port check
- [x] hidden regular file under `/dev`
- [x] directory link-count vs readdir mismatch
- [x] file size/stat mismatch
- [x] promiscuous NIC check
- [x] self-hash check for vpsguard binary tamper
- [x] ransomware extension rename detection
- [x] ransom-note file detection
- [x] mass-delete detection

### Local Operator Workflow

- [x] `vpsguard status`
- [x] `vpsguard logs`
- [x] `vpsguard test-alert`
- [x] `vpsguard test-event`
- [x] `vpsguard version`
- [x] plain-English alert guidance
- [x] Fail2Ban/operator guidance stays text-only
- [x] vpsguard executes no firewall or destructive response commands

---

## Not In Active Roadmap

These are intentionally not promised right now:

- distro package-manager repository publishing
- kernel eBPF probes for `commit_creds`, `cap_capable`, `tty_write`, or packet
  payload inspection
- dashboard, frontend, SaaS account, hosted API, or central database
- remote command execution
- automatic IP blocking or firewall management
- process killing, file quarantine, or user lockout
- Windows/macOS agents
- full Kubernetes/container security platform
- full SIEM or long-term event warehouse

---

## North-Star Test

| Incident step | vpsguard detector |
|---------------|-------------------|
| Attacker SSHs in from a new IP | SSH log parser + first-seen IP |
| Attacker brute-forces credentials | SSH brute-force/user-enum correlation |
| Attacker adds an SSH key | filewatch/FIM on authorized_keys |
| Attacker adds cron persistence | cron filewatch/FIM |
| Attacker adds a systemd service | systemd filewatch/FIM |
| Attacker drops miner in `/tmp` or `/dev/shm` | process path + miner name + CPU/network signals |
| CPU spikes from miner | sustained CPU detector |
| VPS starts attacking other servers | outbound SSH/SMTP/RDP/network spike detectors |
| Attacker tampers with logs/config/binary | filewatch/FIM/audit/self-hash/rootkit checks |
| Attacker kills the agent | systemd/watchdog plus optional healthcheck silence |

All active roadmap items are complete in this repository. Future research can
add deeper kernel visibility, but the current product is already a real VPS
monitoring and alerting agent.
