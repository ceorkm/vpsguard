# Wazuh Analysis for vpsguard

Source: `/Users/femi/Vps-guard/references/wazuh/` (5.x checkout)

## Important Note

This is Wazuh 5.x. The classic XML ruleset (`ruleset/rules/0095-sshd_rules.xml`, etc.) is **gone** — detection logic moved into a C++ engine (logpar combinators). Only `ruleset/sca/` and `ruleset/mitre/` are present here. SCA YAML and rootcheck C are still vpsguard gold.

## License

**GPL v2** (with OpenSSL exception). `LICENSE` lines 26–32 clarify restrictions only apply on **redistribution**. To keep vpsguard MIT-licensable, **reimplement algorithms in Go** instead of copying C/YAML verbatim. Acknowledge Wazuh as inspiration in code comments.

---

## 1. SSH Hardening Checks (SCA YAML)

`ruleset/sca/generic/sca_distro_independent_linux.yml` — 4,999 lines of CIS-style checks. Highlights:

| SCA ID | Check | Pattern |
|--------|-------|---------|
| 36141 | sshd_config perms | `c:stat -Lc "%a %A %u %U %g %G" /etc/ssh/sshd_config -> r:600 && r:0 root 0 root` |
| 36143 | LogLevel VERBOSE/INFO | `c:sshd -T -> r:^\s*LogLevel\s+VERBOSE\|^\s*loglevel\s+INFO` |
| 36144 | X11Forwarding no | `c:sshd -T -> r:^\s*x11Forwarding\s*\t*no` |
| 36145 | MaxAuthTries ≤ 4 | `c:sshd -T -> n:^MaxAuthTries\s*\t*(\d+) compare <= 4` |
| 36146 | IgnoreRhosts yes | `c:sshd -T -> r:ignorerhosts\s*\t*yes` |
| 36147 | HostbasedAuth no | `c:sshd -T -> r:HostbasedAuthentication\s*\t*no` |
| 36148 | PermitRootLogin no | `c:sshd -T -> r:PermitRootLogin\s*\t*no` |
| 36149 | PermitEmptyPasswords no | `c:sshd -T -> r:PermitEmptyPasswords\s*\t*no` |
| 36151 | Weak Ciphers banned | `c:sshd -T -> r:^Ciphers && r:3des-cbc\|aes128-cbc\|...` |
| 36152 | Weak MACs banned | `r:MACs && r:hmac-md5\|hmac-sha1\|...` |
| 36153 | Weak KexAlgorithms | `r:kexalgorithms && r:diffie-hellman-group1-sha1\|...` |
| 36154 | ClientAlive timeout | `n:ClientAliveInterval\s*\t*(\d+) compare <= 300` |
| 36155 | SSH access limited | `f:/etc/ssh/sshd_config -> r:^\s*AllowUsers` |
| 36156 | Banner configured | `r:^\s*Banner\s*\t*/etc/issue\.net` |
| 36158 | AllowTcpForwarding no | `r:AllowTcpForwarding\s*\t*no` |

**vpsguard port:** Parse `/etc/ssh/sshd_config` at startup + on inotify change. Alert on weak settings. Watch `/var/log/auth.log` for:

```re
Failed password for (?:invalid user )?(\S+) from ([\d.]+) port \d+
Accepted \w+ for (\S+) from ([\d.]+) port \d+
Invalid user (\S+) from ([\d.]+)
session opened for user (\S+) by
```

---

## 2. Crypto-Miner Detection

**Not present** in this Wazuh checkout. Only MITRE ATT&CK references in `ruleset/mitre/enterprise-attack.json` (Linux Rabbit, Miner-C — intelligence data, not detection).

**vpsguard implements from scratch:**
- Process names: `xmrig`, `minerd`, `kdevtmpfsi`, `kinsing`, `cryptonight`, `stratum+tcp`
- Outbound ports: 3333, 4444, 5555, 7777, 14444, 45700 (mining pools)
- CPU: sustained >80% from non-root single process
- Executables in `/tmp` or `/dev/shm`

---

## 3. Rootcheck (C source — port to Go)

`src/rootcheck/src/`

### 3a. Hidden PID detection — `check_rc_pids.c:86-263`

```
For PID 1..MAX_PID:
  _kill0   = kill(pid, 0) != ESRCH
  _gsid0   = getsid(pid) != ESRCH
  _gpid0   = getpgid(pid) != ESRCH
  _proc_stat   = lstat("/proc/<pid>") OK
  _proc_read   = opendir, read "/proc/<pid>"
  _proc_opendir = wopendir("/proc/<pid>")
  _ps0     = system("ps -p <pid>") == 0

ALERT:
  kill works but getsid doesn't (or vice versa)  -> "kernel-level rootkit"
  /proc inconsistency                             -> "hidden from /proc"
  kill/getsid work but ps doesn't show            -> "trojaned ps"
```

Go port: ~30 lines. Walk `/proc`, compare with `kill(pid, 0)`. Any PID visible to `kill` but absent from `/proc` = alert.

### 3b. Hidden port detection — `check_rc_ports.c:89-138`

```
For port 0..65535 (TCP+UDP):
  bind(port) -> if fails, port is open
  netstat-equivalent doesn't show -> ALERT "kernel-level rootkit"
```

Go port: use `ss -tlnpu` parsing vs `bind()` attempt.

### 3c. Filesystem anomaly — `check_rc_sys.c:40-540`

Scan `/bin /sbin /usr/bin /usr/sbin /dev /lib /etc /root /var/log /var/mail /var/lib /var/www /usr/lib /usr/include /tmp /boot /usr/local /var/tmp /sys`:

- `lstat(dir).st_nlink` vs `readdir(dir)` count → mismatch = hidden files
- `lstat(file)` ENOENT but readdir shows it → "anomaly"
- Read file vs `st_size` → mismatch = kernel rootkit
- Match against known-rootkit filenames

### 3d. `/dev` regular files — `check_rc_dev.c`

Walk `/dev` recursively. Any `S_ISREG` file (not in allowlist) → ALERT "Possible hidden file."

### 3e. Promiscuous NIC — `check_rc_if.c`

Check interface flags for promiscuous mode (sniffer detection).

---

## 4. FIM (syscheck)

`etc/templates/config/generic/syscheck.agent.template`

### Default watched paths

```
/etc /usr/bin /usr/sbin /bin /sbin /boot
```

### Ignored

```
/etc/mtab /etc/hosts.deny /etc/mail/statistics /etc/random-seed
/etc/random.seed /etc/adjtime /etc/httpd/logs /etc/utmpx /etc/wtmpx
/etc/cups/certs /etc/dumpdates /etc/svc/volatile
```

Regex ignore: `.log$|.swp$`

### Algorithm (`fim_scan.c`, `file.c`, `db/`)

1. **Baseline**: walk dirs, SHA1+SHA256 each file, store in SQLite
2. **Scan** every `frequency` (default 12h): rescan, diff hash + size + mtime + uid/gid + perms + inode
3. **Realtime**: `inotify_add_watch()` for instant alerts (Linux). Optional eBPF whodata captures which process changed it
4. **Alert** on add/delete/modify with before/after

### vpsguard subset (must-watch)

```
/etc/passwd
/etc/shadow
/etc/sudoers
/etc/sudoers.d/
/etc/crontab
/etc/cron.d/
/etc/cron.daily/
/etc/cron.hourly/
/etc/cron.monthly/
/etc/cron.weekly/
/var/spool/cron/
/var/spool/cron/crontabs/
/etc/ssh/sshd_config
/etc/systemd/system/
/lib/systemd/system/
/usr/lib/systemd/system/
/etc/ld.so.preload
/etc/pam.d/
/etc/profile
/etc/bashrc
/etc/bash.bashrc
/root/.ssh/authorized_keys
/root/.bashrc
/root/.bash_profile
/home/*/.ssh/authorized_keys
/home/*/.bashrc
```

Use `fsnotify` + bolt/sqlite for baseline. inotify limit (default 8192) may need bumping via `/proc/sys/fs/inotify/max_user_watches`.

---

## 5. Active Response (FYI — vpsguard alerts only)

`src/active-response/src/`

| Action | Method |
|--------|--------|
| `block-ip-unix` | firewalld → iptables → hosts.deny → route reject (chained fallback) |
| `disable-account` | `passwd -l <user>` |
| `block-ip-macos` | pf rules |
| `block-ip-windows` | Windows Firewall |

Linux IP block chain (`block-ip-unix.c:106-130`):

```
1. firewall-cmd --add-rich-rule "rule family=ipv4 source address=X.X.X.X drop"
2. iptables -I INPUT -s X.X.X.X -j DROP; iptables -I FORWARD -s X.X.X.X -j DROP
3. echo "ALL:X.X.X.X" >> /etc/hosts.deny
4. route add X.X.X.X reject
```

vpsguard reference if a manual "block IP" Telegram command is added later.

---

## 6. Agent ↔ Manager Protocol (NOT useful)

- TCP/UDP port 1514, auth on 1515
- AES-256 or Blowfish per-agent PSK
- zlib compression
- Format: `<agent_id>:<encrypted_payload>`
- 15m disconnection alert default

vpsguard is single-binary. Skip.

---

## 7. Top-20 vpsguard Gold List

| # | Steal | Source | Effort |
|---|-------|--------|--------|
| 1 | SSH auth log regex | reimplement in Go | 1h |
| 2 | Hidden PID detection | `src/rootcheck/src/check_rc_pids.c:86-262` | 2h |
| 3 | FIM watched paths | `etc/templates/config/generic/syscheck.agent.template:9-10` | 30m |
| 4 | FIM critical files | SCA YAML 2973-3006 | 30m |
| 5 | Hidden /dev files | `src/rootcheck/src/check_rc_dev.c:38-57` | 1h |
| 6 | Hidden port detection | `src/rootcheck/src/check_rc_ports.c:50-138` | 2h |
| 7 | Dir link-count vs readdir | `src/rootcheck/src/check_rc_sys.c:510-535` | 1h |
| 8 | File size vs stat mismatch | `src/rootcheck/src/check_rc_sys.c:82-127` | 1h |
| 9 | Heartbeat watchdog (15m) | `etc/wazuh-manager.conf:8` | 30m |
| 10 | sshd_config hardening | SCA YAML 3892, 3836, 3993 | 2h |
| 11 | World-writable root files (S_IWOTH+uid==0) | `check_rc_sys.c:131-165` | 1h |
| 12 | SUID baselining | `check_rc_sys.c:187-192` | 1h |
| 13 | Crontab perm checks | SCA YAML 3513-3583 | 30m |
| 14 | auditd rule verification | SCA YAML 2973-3257 | 1h |
| 15 | /tmp noexec/nosuid mount check | SCA YAML 36008-36011 | 30m |
| 16 | SSH brute-force counter | reimplement | 1h |
| 17 | New user/group detection | parse auth.log | 1h |
| 18 | Promiscuous NIC | `check_rc_if.c` | 1h |
| 19 | Process cmdline miner-string scan | not in Wazuh — implement | 2h |
| 20 | Outbound mining pool ports (3333/4444/5555) | not in Wazuh — `/proc/net/tcp` | 2h |

---

## Key File Paths

```
src/rootcheck/src/check_rc_pids.c    — hidden PID
src/rootcheck/src/check_rc_ports.c   — hidden port
src/rootcheck/src/check_rc_sys.c     — filesystem anomaly
src/rootcheck/src/check_rc_dev.c     — hidden /dev files
src/rootcheck/src/check_rc_if.c      — promiscuous NIC
src/syscheckd/src/fim_scan.c         — FIM scan loop
etc/templates/config/generic/syscheck.agent.template      — FIM paths
etc/templates/config/generic/rootcheck.agent.template     — rootcheck config
ruleset/sca/generic/sca_distro_independent_linux.yml      — SSH/cron/audit
ruleset/sca/ubuntu/cis_ubuntu22-04.yml                    — Ubuntu CIS
src/active-response/src/block-ip-unix.c                   — IP block chain
src/active-response/src/disable-account.c                 — account disable
src/remoted/src/secure.c                                  — agent protocol
src/shared/include/sec.h                                  — AES/Blowfish
LICENSE                                                   — GPL v2
```
