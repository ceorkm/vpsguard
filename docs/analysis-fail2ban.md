# Fail2Ban Analysis for vpsguard

Source: `/Users/femi/Vps-guard/references/fail2ban/`

## License

`COPYING` is **GPL v2**. Python *code* cannot be copied into vpsguard. However, **regex patterns describe log-format facts of third-party software** (OpenSSH, Postfix, nginx, etc.) and are safely portable. Keep attribution comments where patterns are derived.

---

## 1. Filter Regexes — the gold

### sshd.conf — `cmnfailre` (modes: normal/ddos/extra/aggressive)

Path: `config/filter.d/sshd.conf`

Shared variables:
- `__pref = (?:(?:error|fatal): (?:PAM: )?)?`
- `__suff = (?: (?:port \d+|on \S+|\[preauth\])){0,3}\s*`
- `__on_port_opt = (?: (?:port \d+|on \S+)){0,2}`
- `__authng_user = (?: (?:by|from))?(?: (?:invalid|authenticating) user <F-USER>\S+|.*?</F-USER>)?(?: from)?`
- `__alg_match = (?:(?:\w+ (?!found\b)){0,2}\w+)`
- `__pam_auth = pam_[a-z]+`

Core failure patterns (all modes):

```
^[aA]uthentication (?:failure|error|failed) for <F-USER>.*?</F-USER> (?:from )?<HOST>( via \S+)?__suff$
^User not known to the underlying authentication module for <F-USER>.*?</F-USER> (?:from )?<HOST>__suff$
^Failed \S+ for (?P<cond_inv>invalid user )?<F-USER>(?P<cond_user>\S+)|...from <HOST>__on_port_opt(?: ssh\d*)?
^<F-USER>ROOT</F-USER> LOGIN REFUSED FROM <HOST>
^[iI](?:llegal|nvalid) user <F-USER>.*?</F-USER> (?:from )?<HOST>__suff$
^User <F-USER>\S+|.*?</F-USER> (?:from )?<HOST> not allowed because not listed in AllowUsers__suff$
^User <F-USER>\S+|.*?</F-USER> (?:from )?<HOST> not allowed because listed in DenyUsers__suff$
^User <F-USER>\S+|.*?</F-USER> (?:from )?<HOST> not allowed because not in any group__suff$
^refused connect from \S+ \(<HOST>\)
^Received disconnect from <HOST>__on_port_opt:\s*3: .*: Auth fail__suff$
^User <F-USER>\S+|.*?</F-USER> (?:from )?<HOST> not allowed because a group is listed in DenyGroups__suff$
^User <F-USER>\S+|.*?</F-USER> (?:from )?<HOST> not allowed because none of user's groups are listed in AllowGroups__suff$
^<F-NOFAIL>pam_[a-z]+\(sshd:auth\):\s+authentication failure;</F-NOFAIL>(?:\s+(?:(?:logname|e?uid|tty)=\S*)){0,4}\s+ruser=<F-ALT_USER>\S*</F-ALT_USER>\s+rhost=<HOST>(?:\s+user=<F-USER>\S*</F-USER>)?__suff$
^maximum authentication attempts exceeded for (?:invalid user )?<F-USER>.*?</F-USER> (?:from )?<HOST>__on_port_opt(?: ssh\d*)?__suff$
^User <F-USER>\S+|.*?</F-USER> not allowed because account is locked__suff
^Disconnecting(?: from)?(?: (?:invalid|authenticating)) user <F-USER>\S+</F-USER> <HOST>__on_port_opt:\s*Change of username or service not allowed:.*\[preauth\]\s*$
^Disconnecting: Too many authentication failures(?: for <F-USER>\S+|.*?</F-USER>)?__suff$
```

DDoS-mode additions (pre-auth probing):

```
^(?:Did not receive identification string from|Timeout before authentication for(?: connection from)?) <HOST>
^kex_exchange_identification: (?:read: )?(?:[Cc]lient sent invalid protocol identifier|[Cc]onnection (?:closed by remote host|reset by peer))
^Bad protocol version identification '(?:[^']|.*?)' (?:from )?<HOST>__suff$
^(?:banner exchange|ssh_dispatch_run_fatal): Connection from <HOST>__on_port_opt: (?:invalid format|(?:message authentication code incorrect|[Cc]onnection corrupted) \[preauth\])
```

Extra-mode additions:

```
^Received disconnect from <HOST>__on_port_opt:\s*14: No(?: supported)? authentication methods available
^Unable to negotiate with <HOST>__on_port_opt: no matching __alg_match found.
^Unable to negotiate a __alg_match
^no matching __alg_match found:
```

### dovecot.conf — IMAP/POP3 brute-force

Path: `config/filter.d/dovecot.conf`

```
^authentication failure; logname=<F-ALT_USER1>\S*</F-ALT_USER1> uid=\S* euid=\S* tty=dovecot ruser=<F-USER>\S*</F-USER> rhost=<HOST>(?:\s+user=<F-ALT_USER>\S*</F-ALT_USER>)?\s*$
^(?:Login aborted|Aborted login|Disconnected|Remote closed connection|Client has quit the connection)_bypass_reject_reason \((?:auth failed, \d+ attempts(?: in \d+ secs)?|tried to use (?:disabled|disallowed) \S+ auth|proxy dest auth failed)\)[^:]*:(?: user=<<F-USER>[^>]*</F-USER>>,)?(?: method=\S+,)? rip=<HOST>(?:[^>]*(?:, session=<\S+>)?)\s*$
^pam\(\S+,<HOST>(?:,\S*)?\): pam_authenticate\(\) failed: (?:User not known to the underlying authentication module: \d+ Time\(s\)|Authentication failure \([Pp]assword mismatch\?\)|Permission denied)\s*$
^[a-z\-]{3,15}\(\S*,<HOST>(?:,\S*)?\): (?:[Uu]nknown user|[Ii]nvalid credentials|[Pp]assword mismatch)
```

### postfix.conf — SMTP/SASL

```
^[A-Z]{4,} from [^[]*\[<HOST>\](?::\d+)?: [45][50][04] [45]\.\d\.\d+ (?:...): (?:Service unavailable|Access denied|Client host rejected|Relay access denied|need fully-qualified hostname|match|User unknown|Undeliverable address)\b
^[^[]*\[<HOST>\](?::\d+)?: SASL ((?i)LOGIN|PLAIN|(?:CRAM|DIGEST)-MD5) authentication failed:(?! Connection lost to authentication server| Invalid authentication mechanism)
^(?:Message delivery request|Connection) rate limit exceeded: \d+ from [^[]*\[<ADDR>\]
^[A-Z]{4,} from [^[]*\[<HOST>\](?::\d+)?: [45]54 [45]\.7\.1 Service unavailable; Client host \[\S+\] blocked\b
```

### nginx filters

```
# nginx-http-auth.conf
^user "<F-USER>(?:[^"]+|.*?)</F-USER>":? (?:password mismatch|was not found in "[^\"]*")$
^(?:PAM: )?user '<F-USER>(?:[^']+|.*?)</F-USER>' - not authenticated: Authentication failure$

# nginx-limit-req.conf
^%(__prefix_line)s(?:limiting|delaying) (?:request|connection)s?(?:, excess: [\d\.]+,?)? by zone "...", client: <ADDR>,

# nginx-bad-request.conf
^<HOST> - \S+ \[\] "[^"]*" 400

# nginx-botsearch.conf
^<HOST> \- \S+ \[\] \"(GET|POST|HEAD) \/<block> \S+\" 404 .+$
```

### apache-auth.conf

```
^client (?:denied by server configuration|used wrong authentication scheme)\b
^user (?!`)<F-USER>(?:\S*|.*?)</F-USER> (?:auth(?:oriz|entic)ation failure|not found|denied by provider)\b
^Authorization of user <F-USER>(?:\S*|.*?)</F-USER> to access .*? failed\b
^([A-Z]\w+: )?user <F-USER>(?:\S*|.*?)</F-USER>: password mismatch\b
```

### apache-shellshock.conf

```
^warning: HTTP_[^:]+: ignoring function definition attempt(, referer: \S+)?\s*$
^error importing function definition for `HTTP_[^']+'(, referer: \S+)?\s*$
```

### recidive.conf — repeat offenders (vpsguard ThreatScore concept)

```
^%(__prefix_line)s(?:\s*fail2ban\.actions\s*%(__pid_re)s?:\s+)?NOTICE\s+\[<_jailname>\]\s+Ban\s+<HOST>
```

Used with `bantime=1w`, `findtime=1d`. Maps to vpsguard ThreatScore: keep `ip -> ban_count` map and escalate after N bans.

### pam-generic.conf — two-phase match pattern

```
prefregex: ^%(__prefix_line)s\(?pam_unix(?:\(\S+\))?\)?:?\s+authentication failure;(?:\s+(?:(?:logname|e?uid)=\S*)){0,3} tty=\S* <F-CONTENT>.+</F-CONTENT>$
failregex: ^ruser=<F-ALT_USER>(?:\S*|.*?)</F-ALT_USER> rhost=<HOST>(?:\s+user=<F-USER>(?:\S*|.*?)</F-USER>)?\s*$
```

Two-phase prefix scan + extraction is a useful Go pattern (cheap prefix match before expensive regex).

### proftpd.conf / vsftpd.conf / mysqld-auth.conf / dropbear.conf

Patterns extracted; see source files. Useful if VPS owner runs FTP/MySQL/Dropbear.

---

## 2. Jail Defaults

Path: `config/jail.conf`

| Parameter | Default | Notes |
|-----------|---------|-------|
| `bantime` | `10m` | initial ban duration |
| `findtime` | `10m` | sliding window to count failures |
| `maxretry` | `5` | failures before ban |
| `bantime.formula` | `ban.Time * (1<<(ban.Count if ban.Count<20 else 20)) * banFactor` | exponential growth |
| `bantime.multipliers` | optional `1 2 4 8 16 32 64` | step multiplier |
| `bantime.increment` | `false` (default off) | enables exponential ban |

Per-jail overrides:
- `apache-badbots`: `bantime=48h`, `maxretry=1`
- `apache-shellshock`: `maxretry=1`
- `portsentry`: `maxretry=1`
- `recidive`: `bantime=1w`, `findtime=1d`

**Recommended vpsguard defaults:**
- SSH: `findtime=10m`, `maxretry=5`, `bantime=10m` (with exponential growth)
- Web attacks: `findtime=10m`, `maxretry=2-3`, `bantime=1h`
- Known-bad bots / shellshock: `maxretry=1` (instant alert)
- Recidive tier: `findtime=24h`, `maxretry=3`, `bantime=7d`

---

## 3. Action catalog (FYI — vpsguard only alerts)

`config/action.d/` (66 files): iptables, nftables, firewalld, cloudflare, abuseipdb reporting, mail, sendmail, apprise, ufw, pf, shorewall, route, hostsdeny.

---

## 4. Date Pattern Handling

Files: `fail2ban/server/datedetector.py`, `fail2ban/server/datetemplate.py`

Top syslog/log timestamp formats to implement in Go:

| Priority | Pattern | Example |
|----------|---------|---------|
| 1 | `%Y[-/.]%m[-/.]%d(?:T| ?)%H:%M:%S(?:[.,]%f)?(?:\s*%z)?` | `2025-05-02T21:59:59.981` |
| 2 | `(?:%a )?%b %d %k:%M:%S(?:\.%f)?(?: %Y)?` | `May  2 21:59:59` (syslog) |
| 3 | `(?:%a )?%b %d %Y %k:%M:%S(?:\.%f)?` | `Sun May  2 2025 21:59:59` |
| 4 | `%d[-/]%m[-/](?:%Y\|%y) %k:%M:%S` | `02/05/2025 21:59:59` |
| 5 | `%d[-/]%b[-/]%Y[ :]?%H:%M:%S(?:\.%f)?(?: %z)?` | `02/May/2025:09:22:55 -0000` (Apache access) |
| 6 | `%m/%d/%Y:%H:%M:%S` | `05/02/2025:01:57:39` (cPanel) |
| 7 | `EPOCH` | unix integer (audit.log) |
| 8 | `%H:%M:%S` (line-begin anchored) | `21:59:59` |
| 9 | `%y%m%d  ?%H:%M:%S` | `250502 11:46:11` (MySQL) |
| 10 | `TAI64N` | `@400000003b4a39c23294b4a0` (Dovecot/qmail) |

Use a **weight-sorting cache** — re-sort precompiled regex slice by hit count. Try line-begin anchored versions first.

---

## 5. vpsguard Top-10 Port List

1. **sshd.conf `cmnfailre` block** — 15+ patterns covering every OpenSSH failure variant. Single most valuable port.
2. **sshd.conf `mdre-ddos`** — pre-auth probing (port-scanners, SSH fingerprinters).
3. **sshd.conf `mdre-extra`** — alg-mismatch + no-auth-methods probing.
4. **postfix SASL pattern** — email brute-force (very common on VPS).
5. **dovecot auth-failed** — IMAP/POP3 brute-force.
6. **Date detection: syslog format** — covers 90%+ Linux VPS log lines, must be first.
7. **recidive pattern** — repeat-offender escalation; map directly to vpsguard ThreatScore.
8. **nginx-http-auth + nginx-limit-req** — most VPS owners run nginx.
9. **apache-shellshock** — `maxretry=1` instant alert (still actively scanned).
10. **pam-generic two-phase prefregex/failregex** — Go architecture pattern: cheap prefix scan before full regex.

---

## Top 5 ready-to-port Go regexes

Replace `<HOST>` → `(?P<host>...)`, `<F-USER>...</F-USER>` → `(?P<user>...)`.

```re
# 1. SSH invalid user
^Failed \S+ for (?P<cond_inv>invalid user )?(?P<user>\S+) from (?P<host>\S+) port \d+(?: ssh\d*)?

# 2. SSH max auth attempts exceeded
^maximum authentication attempts exceeded for (?:invalid user )?(?P<user>.*?) from (?P<host>\S+)(?: port \d+)?(?: ssh\d*)?(?: \[preauth\])?\s*$

# 3. SSH DDoS — timeout / no identification
^(?:Did not receive identification string from|Timeout before authentication for(?: connection from)?) (?P<host>\S+)

# 4. Postfix SASL brute-force
^.*\[(?P<host>[^\]]+)\](?::\d+)?: SASL (?i:LOGIN|PLAIN|(?:CRAM|DIGEST)-MD5) authentication failed:(?! Connection lost to authentication server| Invalid authentication mechanism)

# 5. Dovecot IMAP/POP3 auth failure
^(?:Login aborted|Aborted login|Disconnected).*\(auth failed, \d+ attempts(?: in \d+ secs)?\)[^:]*:(?: user=<[^>]*>,)?(?: method=\S+,)? rip=(?P<host>\S+)
```

Use ordered slice of precompiled `*regexp.Regexp`, re-sort by hit frequency. Implement syslog date pattern first.
