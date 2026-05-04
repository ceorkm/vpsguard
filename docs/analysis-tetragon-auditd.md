# Tetragon + audit-userspace Analysis for vpsguard

## PART 1 — Tetragon

Source: `/Users/femi/Vps-guard/references/tetragon/`

### License

**Apache 2.0**. Compatible with embedding in OSS or commercial products.

### TracingPolicy Examples (`examples/tracingpolicy/`)

| Policy | Catches |
|--------|---------|
| `filename_monitoring.yaml` | `security_file_permission`, `security_mmap_file`, `security_path_truncate` on `/etc/` |
| `openat_write.yaml` | `sys_openat` on `/etc/passwd` w/ write/create flags |
| `lsm_file_open.yaml` | LSM `file_open` on shadow/passwd opened by cat |
| `sys_setuid.yaml` | `sys_setuid` |
| `process.credentials.changes.at.syscalls.yaml` | All `setuid/setgid/setreuid/setregid/setresuid/setresgid/setfsuid/setfsgid` |
| `kprobe_commit_creds.yaml` | `commit_creds()`, `override_creds()`, `revert_creds()` — every kernel cred install |
| `creds-capability-usage.yaml` | `cap_capable()` — every kernel capability check |
| `process-exec/process-exec-elf-begin.yaml` | `security_bprm_creds_from_file` |
| `tcp-connect.yaml` | `tcp_connect`, `tcp_close`, `tcp_sendmsg` |
| `tcp-listen.yaml` | `inet_csk_listen_start` (ports 1337/31337) |
| `tcp-accept.yaml` | `tcp_set_state`, `tcp_create_openreq_child` |
| `security-socket-connect.yaml` | LSM `security_socket_connect` |
| `raw_syscalls.yaml` | tracepoint `sys_enter` — all syscalls |
| `sys_mount.yaml` | `sys_mount` — escape vector |
| `sys_pivot_root.yaml` | container escape |
| `sys_ptrace.yaml` | `sys_ptrace` — injection |
| `sys_clock_settime.yaml` | time tampering |
| `host-changes/monitor-kernel-modules.yaml` | `security_kernel_module_request`, `do_init_module`, `free_module` |
| `host-changes/monitor-signed-kernel-modules.yaml` | unsigned module loads |
| `tty.yaml` | `tty_write` — keystroke capture |
| `loader.yaml` | dynamic linker activity |
| `security_inode_follow_link.yaml` | symlink/hardlink attacks |
| `cves/cve-2023-2640-overlayfs-ubuntu.yaml` | Ubuntu OverlayFS privesc |
| `cves/cve-2024-3094-xz-ssh.yaml` | XZ/SSH backdoor |

### Built-in (no policy needed)

Always tracks: every `execve` (binary, args, cwd, env, UID, AUID, namespaces), fork (`wake_up_new_task`), exit (`acct_process`), and creds at `security_bprm_committing_creds`.

### eBPF programs (`bpf/process/`)

| File | Hook | Point |
|------|------|-------|
| `bpf_execve_event.c` | tracepoint | `sys_execve` |
| `bpf_fork.c` | kprobe | `wake_up_new_task` |
| `bpf_exit.c` | kprobe | `acct_process`, `disassociate_ctty` |
| `bpf_execve_bprm_commit_creds.c` | kprobe | `security_bprm_committing_creds` |
| `bpf_enforcer.c` | fmod_ret | `security_task_prctl` |
| `bpf_generic_kprobe.c` | kprobe/kretprobe | any kernel function |
| `bpf_generic_lsm_core.c` | lsm | any LSM hook |
| `bpf_generic_lsm_ima_*.c` | lsm.s | IMA verification |
| `bpf_generic_rawtp.c` | raw_tp | tracepoint |
| `bpf_generic_tracepoint.c` | tracepoint | any |
| `bpf_generic_fentry.c` / `_fexit.c` | fentry/fexit | any kernel fn |
| `bpf_generic_uprobe.c` | uprobe | userspace |
| `bpf_generic_usdt.c` | usdt | USDT probes |
| `bpf_cgroup.c` | raw_tracepoint | `cgroup_rmdir` |

### Process exec tracking — the crown jewel

`tracepoint/sys_execve` populates `execve_map` keyed by `{pid, ktime}`. On exec, BPF calls `event_find_parent()` to fill in the full ancestor chain — captured **in kernel context before userspace can tamper**.

Userspace Go (`pkg/process/process.go:413`): every event has `parent_exec_id` from `GetExecIDFromKey(&parent)`. Protobuf API (`tetragon.proto:314-316`) exposes `process`, `parent`, `repeated ancestors` on every `ProcessExec`, `ProcessKprobe`, `ProcessTracepoint`, `ProcessLsm`, `ProcessExit`.

vpsguard alert payoff: `nginx → php-fpm → /bin/bash → /bin/nc` on every Telegram message. Cryptographically linked exec_ids.

### Kernel version requirements

| Feature | Minimum |
|---------|---------|
| Tetragon baseline (execve, fork, kprobe) | **4.19** |
| Recommended | **5.10+** |
| BTF/CO-RE (`CONFIG_DEBUG_INFO_BTF=y`) | ~5.8 |
| kretprobe | 5.4+ |
| LSM BPF hooks | **5.7** |
| BPF fentry/fexit | 5.5+ |
| IMA via LSM+BPF | **5.11** |
| arm64 full exec args | 5.10+ |
| cgroup v1 on ≥6.11 | needs `CONFIG_MEMCG_V1=y` |

vpsguard runtime gating: `tetra probe`-style detection, fall back to inotify/fanotify on old kernels.

### vpsguard v2 eBPF wishlist (top 10)

1. Full process ancestry on every alert
2. LSM `file_open` on sensitive paths (catches renamed/hardlinked access inotify misses)
3. `commit_creds` kprobe — instant privesc alert
4. `cap_capable` monitoring — capability checks
5. TCP connect/accept tracking — reverse shells
6. `sys_ptrace` detection — injection
7. Kernel module load (`do_init_module`, `free_module`) — rootkit
8. `sys_pivot_root`/`sys_mount` — container escape
9. `tty_write` capture — attacker keystrokes for forensic trail
10. Inline blocking via `Override`/`Sigkill` actions (kernel 5.3+ for signal, 5.7+ for LSM override)

---

## PART 2 — audit-userspace

Source: `/Users/femi/Vps-guard/references/audit-userspace/`

### License

- `COPYING` — **GPL v2** (auditd, auditctl, ausearch, aureport, src/)
- `COPYING.LIB` — **LGPL v2.1** (`auparse/`, `lib/libaudit`)

LGPL allows linking via cgo without source disclosure for OSS or closed binaries (with re-link ability for static).

### Default rule sets (`rules/`)

| File | Purpose |
|------|---------|
| `10-base-config.rules` | flush, set buffer, failure mode |
| `10-no-audit.rules` | minimal, no syscall audit |
| `11-loginuid.rules` | loginuid immutability |
| `20-dont-audit.rules` | suppress cron/chrony/key noise |
| `21-no32bit.rules` | block 32-bit syscalls on 64-bit |
| `30-ospp-v42.rules` (+ split) | OSPP profile |
| `30-pci-dss-v31.rules` | PCI-DSS — setuid exec, account changes |
| `30-stig.rules` | STIG — time/identity/perm/access/sudoers/systemd-run |
| `31-privileged.rules` | watches on setuid binaries (find-generated) |
| `32-power-abuse.rules` | root reads /home |
| `41-containers.rules` | container-specific |
| `42-injection.rules` | `ptrace` |
| `43-module-load.rules` | `init_module`, `finit_module`, `delete_module` |
| `44-installers.rules` | package manager activity |
| `71-networking.rules` | network config changes |
| `99-finalize.rules` | immutable mode (`-e 2`, commented out) |

### Rules vpsguard ships (`/etc/audit/rules.d/80-vpsguard.rules`)

```
# Identity
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# SSH keys
-w /root/.ssh/authorized_keys -p wa -k ssh-key-mod
-w /root/.ssh/ -p wa -k ssh-key-mod
# auditd has no glob — vpsguard uses inotify for /home/*/.ssh/

# Cron
-w /etc/cron.d/ -p wa -k cron-mod
-w /etc/cron.daily/ -p wa -k cron-mod
-w /etc/cron.hourly/ -p wa -k cron-mod
-w /etc/crontab -p wa -k cron-mod
-w /var/spool/cron/ -p wa -k cron-mod

# Systemd
-w /etc/systemd/system/ -p wa -k systemd-mod
-w /lib/systemd/system/ -p wa -k systemd-mod
-w /usr/lib/systemd/system/ -p wa -k systemd-mod

# Setuid execve only (low volume, high signal)
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=setuid-exec
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=setuid-exec

# chmod/chown sensitive paths
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F dir=/etc -F key=perm-mod-etc
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F dir=/etc -F key=perm-mod-etc
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F path=/root/.ssh/authorized_keys -F key=perm-mod-ssh
```

### Immutable mode (`-e 2`)

In `99-finalize.rules` (commented out by default). When active: rules can't be changed until reboot, even by root. Attempted modifications return `EPERM`. Recommended for production once vpsguard rules are stable. Trade-off: no rule reload without reboot. Reboot itself triggers a boot-time alert (audit log watch).

### auparse library

`auparse/` — full C library, LGPL 2.1. `auparse_init()` accepts `AUSOURCE_LOGS` (reads audit.log directly), `AUSOURCE_FILE`, `AUSOURCE_FEED` (streaming via `auparse_feed()`), `AUSOURCE_DESCRIPTOR`. Has `auparse_normalize()`, field interpretation, callback API.

### Recommendation for vpsguard

**Ship our own rules + tail audit.log directly in Go. Require auditd as dependency.**

Why:
- auditd already on every major distro (RHEL/Debian/Ubuntu)
- Integrates kernel netlink at lowest level — works on kernel 3.x+
- No eBPF/BTF requirement
- Drop-in rules file `/etc/audit/rules.d/80-vpsguard.rules` installs with the release package or raw installer
- Tail `/var/log/audit/audit.log` with small Go parser keying on `key=identity|ssh-key-mod|cron-mod|systemd-mod|actions|setuid-exec|perm-mod-*`
- No cgo, no kernel headers, < 1 sec alert latency
- Reserve inotify/fanotify reimpl for v2 zero-dependency mode + paths auditd can't glob (`/home/*/.ssh/`)

---

## Summary — Tetragon vs audit-userspace for vpsguard

| Capability | auditd (v1) | Tetragon (v2) |
|------------|-------------|---------------|
| Kernel requirement | 3.x+ | 4.19+, ideally 5.10+ |
| Cgo / kernel deps | none if tail log | requires libbpf, BTF |
| Process ancestry | partial (PID, ppid only) | **full chain via execve_map** |
| File watches | path-based, no globs | LSM hooks catch renames/hardlinks |
| Privesc detection | post-fact (audit.log) | **realtime via commit_creds** |
| Network detection | no | TCP connect/accept hooks |
| Module load | `init_module` syscall | `do_init_module` kernel fn |
| Inline blocking | no | `Override`/`Sigkill` (kernel 5.7+) |
| Distro coverage | universal | modern only |
| vpsguard fit | **MVP / v1** | **v2 / v3** |

**Plan:** vpsguard ships auditd integration + own rules + log tail in pure Go. Tetragon-style eBPF remains research only, not an active product commitment. vpsguard does not do inline blocking.
