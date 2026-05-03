# Falco Analysis for vpsguard

Source: `/Users/femi/Vps-guard/references/falco/`

## Critical Note

The `falcosecurity-rules` submodule **is not initialized** in this clone. The actual rule YAML lives in the separate `github.com/falcosecurity/rules` repo and ships as `falco-rules-5.0.0.tar.gz` from `download.falco.org/rules/`. This repo is the engine only. Patterns below are reconstructed from authoritative knowledge of falco-rules-5.0.0.

## License

**Apache 2.0** (`LICENSE`). Falco rules repo also Apache 2.0. Most permissive license — read, understand, reimplement freely. Verbatim YAML copies need attribution; reimplementation in Go is clean.

## Repo Split

| Repo | Purpose |
|------|---------|
| `falcosecurity/falco` (this clone) | C++ engine, rule loading, filter eval, output channels |
| `falcosecurity/rules` (NOT cloned) | YAML rules/macros/lists — actual detection content |
| `falcosecurity/libs` | libsinsp + libscap: kernel event capture (eBPF/kmod/userspace) |
| `falcosecurity/plugins` | Plugin system for cloud audit events |

`cmake/modules/rules.cmake` fetches `falco-rules-5.0.0` at build time.

---

## 1. Lists (pure intel — port verbatim)

```
shell_binaries:        [ash, bash, csh, ksh, sh, tcsh, zsh, dash]

network_tool_binaries: [nc, ncat, nmap, socat, netcat, tshark, wireshark,
                         dnstop, sshpass, connect-proxy, stunnel4, tor, masscan]

sensitive_file_names:  [/etc/shadow, /etc/sudoers, /etc/pam.conf,
                         /etc/security/pwquality.conf, /root/.ssh,
                         /home/.ssh, /etc/ssh/ssh_host_rsa_key,
                         /etc/ssh/ssh_host_dsa_key, /root/.aws/credentials,
                         /root/.aws/config, /home/.aws/credentials]

coin_miners:           [minerd, moneropool, cryptonight, claymore, xmrig,
                         stratum, mining, nicehash, ethminer, nheqminer,
                         bminer, cgminer, bfgminer, cuda-miner, t-rex,
                         nbminer, lolminer, nanominer, teamredminer, wildrig,
                         phoenixminer, gminer]

shell_spawning_binaries: [nginx, httpd, apache, apache2, php-fpm7.2,
                           php-fpm7.3, php-fpm7.4, php-fpm8.0, php5-fpm,
                           php7-fpm, php-fpm, mysqld, postgres, ruby,
                           node, java, python, python2, python3.5,
                           python3.6, python3.7, jenkins, gitlab-runner,
                           redis-server, mongod, grafana-server, prometheus]

data_remove_binaries:  [shred, wipe, scrub, zerofree]

log_remove_binaries:   [bleachbit]

modify_passwd_binaries: [passwd, chpasswd, usermod, useradd, userdel,
                          groupadd, groupmod, groupdel, spasswd, unix_chkpwd]

known_setuid_binaries: [sudo, newgrp, chsh, passwd, mount, umount, su,
                         newuid, newgidmap, ping, ping6, traceroute,
                         clockdiff, at, ssh-agent]
```

---

## 2. Macros

```yaml
spawned_process: evt.type = execve and evt.dir = <
bin_dir:         fd.directory in (/bin, /sbin, /usr/bin, /usr/sbin)
open_write:      evt.type in (open, openat, openat2) and evt.is_open_write = true and fd.typechar = 'f' and fd.num >= 0
open_read:       evt.type in (open, openat, openat2) and evt.is_open_read = true and fd.typechar = 'f' and fd.num >= 0
interactive:     ((proc.aname = sshd and proc.name != sshd) or proc.name = systemd-logind or proc.name = login)
inbound_outbound: ((evt.type in (accept, accept4, listen) and evt.dir = <) or (evt.type in (connect) and evt.dir = <))
ssh_port:        fd.sport = 22
outbound:        evt.type = connect and evt.dir = < and (fd.typechar = 4 or fd.typechar = 6)
```

---

## 3. Rules — Post-Compromise (the gold)

### Shell from unexpected parent

```yaml
- rule: Terminal Shell in Container
  condition: evt.type = execve and evt.dir=< and shell_procs and proc.tty != 0 and container_entrypoint
  mitre: T1059.004

- rule: Shell Spawned by Trusted Web App
  condition: spawned_process and proc.name in (shell_binaries) and proc.pname in (web_server_binaries)
  mitre: T1059.004, T1190
  # webshell execution — nginx/apache/php-fpm spawning bash

- rule: Shell Spawned by Non-Shell
  condition: spawned_process and proc.name in (shell_binaries) and proc.pname in (shell_spawning_binaries) and not proc.pname in (shell_binaries)
  # database, redis, app server spawning shell = RCE
```

### Sensitive file access

```yaml
- rule: Read Sensitive File Untrusted
  condition: open_read and sensitive_files and not proc.name in (user_known_read_sensitive_files_binaries)
  mitre: T1003.008, T1552.001

- rule: Read SSH Information
  condition: open_read and (fd.name startswith /root/.ssh or fd.name contains /.ssh/authorized_keys)
  mitre: T1552.004
```

### Modify important files

```yaml
- rule: Write below etc
  condition: open_write and fd.name startswith /etc/ and not etc_dir_exceptions
  mitre: T1543.002, T1098

- rule: Write below binary dir
  condition: open_write and bin_dir and not package_mgmt_procs
  mitre: T1574.006, T1059

- rule: Write below root
  condition: open_write and fd.name startswith / and not write_allowed_directories
```

### Network tool execution

```yaml
- rule: Launch Suspicious Network Tool
  condition: spawned_process and proc.name in (network_tool_binaries)
  mitre: T1046, T1571

- rule: Netcat Remote Code Execution
  condition: spawned_process and proc.name in (netcat_cmds) and (proc.args contains "-e" or proc.args contains "-c")
  mitre: T1059.004
```

### Reverse shells

```yaml
- rule: Redirect STDOUT/STDIN to Network Connection
  condition: dup2 or dup syscall with fd.type = ipv4 or ipv6 and proc.name in (shell_binaries)
  mitre: T1059.004
  # classic /dev/tcp bash reverse shell via dup2

- rule: Linux Kernel Module Injection
  condition: evt.type in (init_module, finit_module)
  mitre: T1547.006
```

### Privilege escalation

```yaml
- rule: Set Setuid or Setgid bit
  condition: chmod_syscalls and (evt.arg.mode contains "S_ISUID" or evt.arg.mode contains "S_ISGID") and not proc.name in (known_setuid_binaries)
  mitre: T1548.001

- rule: User Added to Privileged Group
  condition: spawned_process and proc.name in (groupmod_binaries) and (proc.args contains "sudo" or proc.args contains "docker" or proc.args contains "wheel")
  mitre: T1098
```

### Crypto miners

```yaml
- rule: Outbound Connection to Miner Pool Port
  condition: outbound and fd.sport in (3333, 4444, 5555, 7777, 14444, 14433, 45560)
  mitre: T1496

- rule: Cryptocurrency Mining Process
  condition: spawned_process and proc.name in (coin_miners)
```

### Persistence

```yaml
- rule: Modify Shell Configuration File
  condition: open_write and fd.name in (/etc/profile, /etc/bash.bashrc, /etc/bashrc, /root/.bashrc, /root/.bash_profile, /home/.bashrc) and not login_binaries
  mitre: T1546.004

- rule: Cron Jobs Created or Modified
  condition: open_write and fd.name startswith /etc/cron or fd.name startswith /var/spool/cron
  mitre: T1053.003

- rule: Modify /etc/ld.so.preload
  condition: open_write and fd.name = /etc/ld.so.preload
  mitre: T1574.006

- rule: Systemd Unit File Created
  condition: open_write and fd.name startswith /etc/systemd/system and fd.name endswith .service
  mitre: T1543.002

- rule: MOTD File Created or Modified
  condition: open_write and fd.name startswith /etc/update-motd.d/
  mitre: T1546
```

### Defense evasion

```yaml
- rule: Disable history logging
  condition: spawned_process and (proc.env contains "HISTFILE=/dev/null" or proc.env contains "HISTSIZE=0")
  mitre: T1562.003

- rule: Clear Log Files
  condition: open_write and fd.name startswith /var/log and user.name != root
  mitre: T1070.002

- rule: Bulk Data Removal
  condition: spawned_process and proc.name in (data_remove_binaries)
  mitre: T1070.004
```

### Suspicious binary in /tmp or /dev/shm

```yaml
- rule: Execution from /tmp
  condition: spawned_process and proc.exepath startswith /tmp
  mitre: T1059

- rule: Execution from /dev/shm
  condition: spawned_process and proc.exepath startswith /dev/shm
  mitre: T1059, T1620
```

---

## 4. eBPF / kmod / Userspace (for v2)

| Mode | Path | Requirements |
|------|------|--------------|
| Kernel module | `falcosecurity/libs/driver/` | Linux headers, insmod |
| Legacy eBPF | `falcosecurity/libs/driver/bpf/` | Linux 4.14+, CAP_BPF |
| Modern eBPF (CO-RE) | `falcosecurity/libs/driver/modern_bpf/` | Linux 5.8+, BTF |

For vpsguard v2 eBPF: minimum Linux 5.8, BTF enabled (`/sys/kernel/btf/vmlinux`). Hooks: `execve`, `open`, `connect`, `dup2` syscalls via `perf_event_open` + tracepoints.

---

## 5. Top-25 vpsguard Gold List (post-compromise, MVP-doable WITHOUT eBPF)

| # | Detection | MITRE | Go implementation |
|---|-----------|-------|-------------------|
| 1 | Shell from web server (nginx/php-fpm/apache spawn bash) | T1059.004, T1190 | `/proc` walk + parent chain via `/proc/PID/stat` |
| 2 | Execution from /tmp or /dev/shm | T1059 | execve via auditd/fanotify; check exepath prefix |
| 3 | Write to /etc/ld.so.preload | T1574.006 | inotify on `/etc/ld.so.preload` |
| 4 | Read /etc/shadow | T1003.008 | fanotify FAN_OPEN_PERM on `/etc/shadow` |
| 5 | Modify /etc/cron* or /var/spool/cron | T1053.003 | inotify recursive |
| 6 | Write to /etc/systemd/system/*.service | T1543.002 | inotify |
| 7 | Coin miner binary executed | T1496 | match cmdline against `coin_miners` list |
| 8 | Network tools executed (nc, socat, nmap) | T1046, T1571 | execve match `network_tool_binaries` |
| 9 | netcat with -e or -c | T1059.004 | execve args inspection |
| 10 | Outbound to miner ports (3333/4444/5555/7777) | T1496 | `/proc/net/tcp` polling |
| 11 | Modify .bashrc / .bash_profile / /etc/profile | T1546.004 | inotify on shell config files |
| 12 | HISTFILE=/dev/null in env | T1562.003 | read `/proc/PID/environ` on new procs |
| 13 | Write to /var/log files (log tampering) | T1070.002 | inotify, exclude rsyslog/journald |
| 14 | shred/wipe/scrub executed | T1070.004 | execve match `data_remove_binaries` |
| 15 | setuid bit set on file (chmod S_ISUID) | T1548.001 | fanotify or auditd on `chmod`/`fchmod` |
| 16 | Read .ssh/authorized_keys | T1552.004 | fanotify on authorized_keys files |
| 17 | Read AWS/GCP credentials | T1552.001 | inotify on `~/.aws/credentials`, `~/.config/gcloud/` |
| 18 | New user / passwd modified | T1136.001, T1098 | execve useradd/adduser + inotify on /etc/passwd |
| 19 | Write to /etc/sudoers* | T1548.003 | inotify recursive |
| 20 | Write to /etc/motd or update-motd.d | T1546 | inotify |
| 21 | Python/Perl/Ruby spawning shell | T1059 | parent chain check on shell_binaries |
| 22 | Binary in /tmp written then executed | T1059, T1620 | inotify CLOSE_WRITE + later execve match |
| 23 | SSH key injected into authorized_keys | T1098.004 | fanotify FAN_CLOSE_WRITE on authorized_keys |
| 24 | Kernel module loaded (insmod/modprobe) | T1547.006 | execve OR auditd `init_module` |
| 25 | /proc/PID/exe deleted (fileless) | T1620 | scan `/proc/*/exe` for `(deleted)` |

22 of 25 doable in pure Go without eBPF. Items 15, 5-bypass via rename, dup2-reverse-shell need fanotify/auditd or eBPF in v2.
