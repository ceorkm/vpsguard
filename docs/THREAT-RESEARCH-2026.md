# VPS threat research snapshot - May 3, 2026

VpsGuard's job remains monitor and alert only. Fail2Ban, firewall policy, provider controls, and the operator handle blocking or cleanup.

## What current VPS compromises look like

| Attack class | Current evidence | What attackers do after access | VpsGuard coverage |
|---|---|---|---|
| SSH brute force and password spray | ASEC Q4 2025 and Q1 2026 SSH honeypot reporting shows Linux SSH servers still receiving brute-force/dictionary attacks that deploy DDoS bots, XMRig, Prometei, P2PInfect, V2Ray, Mirai/Gafgyt/ShellBot-style tooling. | Run recon commands, drop miners/bot clients, connect to IRC/C2, add cron/systemd/SSH keys, erase traces. | SSH failure/success parsing, brute-force/user-enum correlation, first-seen/trusted IPs, success-after-failures, service brute-force logs, cron/systemd/SSH key/FIM/audit/process/network alerts. |
| Exposed Docker API / container environments | Akamai's 2025 Docker API research and Kaspersky Dero-miner reporting show attackers creating containers, mounting host filesystems, downloading Tor-hosted scripts/binaries, modifying SSH config, and running miners or botnet components. | `docker run --privileged`, host mounts, `/var/run/docker.sock` abuse, Tor/torsocks downloaders, XMRig or Dero miners, scanner installation. | New `exposure` detector for public Docker/Kube risky ports, process detection for suspicious Docker host access, audit watch for Docker socket, tmp outbound, miner names, high CPU, miner ports, DNS/known-bad feeds. |
| Exposed PostgreSQL/Redis/databases | Wiz CPU_HU reports exposed PostgreSQL with weak credentials deploying fileless XMRig-C3; Kinsing campaigns continue abusing Redis/Docker/Kubernetes. | Fileless payloads, unique-per-victim binaries, cron persistence, SSH key deletion/addition, config changes, miner execution. | New public exposure detector for Postgres/Redis/MySQL/Mongo/Elasticsearch/Memcached, process credential FD scan, cron/FIM/filewatch, high CPU/miner/network alerts. |
| Web app / admin-panel RCE | Akamai observed fast weaponization of Wazuh CVE into Mirai; Wiz tracks Apache Druid cryptojacking; Hadooken/WebLogic campaigns drop cryptominers plus Tsunami botnet payloads. | `wget`/`curl` shell scripts, `/tmp` ELF payloads, botnet tools, miners, firewall disabling, lateral SSH key collection. | Web parent-chain shell detection, tmp execution + outbound, downloader-piped-to-shell and encoded-payload command detection, exposed WebLogic/admin/dev ports, FIM/filewatch/audit/process/network alerts. |
| Linux cryptominers | Akamai cryptominer analysis and many 2025 reports show XMRig, Kinsing/kdevtmpfsi, perfctl-like naming, pool/proxy infrastructure, and high CPU/resource abuse. | Impersonate system tools, run from `/tmp`/`/dev/shm`, delete binaries, connect to stratum/miner ports, kill competitors, add watchdog persistence. | Miner names/cmdline, sustained CPU, deleted binary, temp path, tmp+outbound, miner ports, bulk outbound, rootkit checks, FIM, cron/systemd alerts. |
| Stealers / credential harvesting | CISA guidance emphasizes collecting SSH keys, cloud creds, Docker config, DNS anomalies, cron/systemd, and Linux logins; supply-chain attacks like Shai-Hulud target developer/cloud credentials in CI and workloads. | Read `.ssh/id_*`, `.aws/credentials`, `.docker/config.json`, `.kube/config`, package-manager tokens, GitHub CLI/git credentials, shell history. | Process FD scan now covers SSH, AWS, Docker, kubeconfig, npm, PyPI, git credentials, GitHub CLI hosts, shell history; audit covers sensitive files and Docker socket. |
| PAM backdoors / auth-layer persistence | 2025 Linux PAM backdoor reporting around Plague-style malware shows attackers abusing authentication modules for stealth access and credential capture. | Modify `/etc/pam.d`, drop modules under security module paths, use obfuscated static credentials. | New filewatch and audit watches for `/etc/pam.d`, `/lib/security`, `/lib64/security`, `/usr/lib/security`; FIM baselines key PAM files. |
| DDoS / IRC botnets | SSHStalker reporting shows IRC-based Linux botnets on cloud infrastructure with brute-force initial access and dormant DDoS/cryptomining capability. ASEC tracks ShellBot/Tsunami/Mirai/Gafgyt-style botnets. | IRC C2, outbound scanning, DDoS traffic, miners, persistence. | Outbound SSH/SMTP/RDP spikes, public tmp process outbound, bulk TX, known-bad IP/domain, DNS tunneling, miner pool ports, process scanner commands. |
| Keylogger / clipboard monitoring | MITRE PAKLOG records clipboard monitoring/extraction; Linux server keylogging tends to show as PAM abuse, `/dev/input` access, TTY/session capture, or suspicious clipboard tools on GUI-capable hosts. | Read clipboard, hook PAM, access input devices, capture sessions. | PAM monitoring, process FD alert on `/dev/input`/`/dev/uinput`, suspicious `xclip`/`xsel`/`wl-paste` command detection. |

## Sources used

- ASEC, "Statistics Report on Malware Targeting Linux SSH Servers in Q4 2025", 2026.
- SecuriTricks/ASEC mirror, "Q1 2026 Malware Statistics Report for Linux SSH Servers", 2026.
- Akamai, "Off Your Docker: Exposed APIs Are Targeted in New Malware Strain", 2025.
- Akamai, "Two Botnets, One Flaw: Mirai Spreads Through Wazuh Vulnerability", 2025.
- Akamai, "Cryptominers' Anatomy: Analyzing Cryptominers", 2025.
- Wiz, "CPU_HU: Fileless cryptominer targeting exposed PostgreSQL", 2025.
- Wiz Threats, "Sysrv Apache Druid cryptojacking", 2025.
- Kaspersky, "Dero crypto miner spreading via exposed container environments", 2025.
- MITRE ATT&CK, "Kinsing" and "PAKLOG".
- Microsoft Security, "Shai-Hulud 2.0: Guidance for detecting, investigating, and defending against the supply chain attack", 2025.
- CISA, "Technical Approaches to Uncovering Malicious Activity".
