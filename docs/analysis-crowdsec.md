# CrowdSec Analysis for vpsguard

Source: `/Users/femi/Vps-guard/references/crowdsec/`

## Important Note

The hub parsers (`sshd-logs.yaml`, `ssh-bf.yaml`, scenario YAMLs) are **NOT** in this repo. They live in the separate `github.com/crowdsecurity/hub` repository. Patterns below are reconstructed from Go test files, syslog parser tests, and community docs. The engine code paths are fully present.

## License

**MIT** — `LICENSE`. Code can be copied verbatim with attribution.

---

## 1. Acquisition (Log Readers)

Path: `pkg/acquisition/modules/`

| Source | Module Path |
|--------|------------|
| file (tail + inotify) | `pkg/acquisition/modules/file/` |
| journalctl (systemd) | `pkg/acquisition/modules/journalctl/` |
| syslog (UDP/TCP server) | `pkg/acquisition/modules/syslog/` |
| docker / cloudwatch / kafka / loki / s3 / k8s / appsec / http | other dirs |

### File tail — `pkg/acquisition/modules/file/run.go`

- Library: `github.com/nxadm/tail` — `ReOpen: true, Follow: true`, handles log rotation
- inotify via `github.com/fsnotify/fsnotify` — watches dir for new files
- Falls back to polling for network filesystems automatically
- Symlink warning: `poll_without_inotify: true` for symlinked files

```go
type Configuration struct {
    Filenames             []string
    ExcludeRegexps        []string `yaml:"exclude_regexps"`
    MaxBufferSize         int      `yaml:"max_buffer_size"`
    PollWithoutInotify    *bool    `yaml:"poll_without_inotify"`
    DiscoveryPollEnable   bool     `yaml:"discovery_poll_enable"`
    DiscoveryPollInterval time.Duration
}
```

### Journald — `pkg/acquisition/modules/journalctl/run.go`

- Spawns `journalctl --follow -n 0 [filters...]` as subprocess
- Reads stdout with `bufio.Scanner`
- Config key: `journalctl_filter` (list of journalctl match expressions)
- Example: `_SYSTEMD_UNIT=sshd.service` (rpm) or `_SYSTEMD_UNIT=ssh.service` (deb)
- Uses `golang.org/x/sync/errgroup` for stdout/stderr goroutines
- Context cancellation propagates cleanly

### vpsguard MVP YAML

```yaml
source: file
filenames:
  - /var/log/auth.log
  - /var/log/secure
labels:
  type: syslog
mode: tail
---
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=sshd.service"
labels:
  type: syslog
```

`config/detect.yaml` (lines 215–271) shows the dual-strategy detection logic: prefer file → fall back to journalctl based on what's available.

---

## 2. Parsers

Path: `pkg/parser/`

### Architecture

Multi-stage YAML pipeline. Nodes have:
- `filter` — expr filter (e.g., `evt.Line.Labels.type == 'syslog'`)
- `grok` — pattern against a field
- `statics` — assignments on match
- `onsuccess: next_stage` — promote event
- `nodes` — child nodes

```go
type NodeConfig struct {
    Stage      string         // s00-raw, s01-parse, s02-enrich
    Filter     string
    OnSuccess  string         // "continue" | "next_stage"
    SubNodes   []NodeConfig
    Grok       GrokPattern
    Statics    []Static
    Stashes    []Stash         // TTL cache for correlation
    Whitelist  Whitelist
}
```

### SSH grok patterns (reconstructed from hub)

```yaml
nodes:
  - grok:
      pattern: "^Failed password for (invalid user )?%{USERNAME:ssh_user} from %{IP:source_ip} port %{INT:source_port} ssh2$"
      apply_on: message
    statics:
      - meta: log_type
        value: ssh_failed-password
      - meta: service
        value: ssh

  - grok:
      pattern: "^Invalid user %{USERNAME:ssh_user} from %{IP:source_ip}(?: port %{INT:source_port})?$"
      apply_on: message
    statics:
      - meta: log_type
        value: ssh_invalid-user

  - grok:
      pattern: "^Accepted password for %{USERNAME:ssh_user} from %{IP:source_ip} port %{INT:source_port} ssh2$"
      apply_on: message
    statics:
      - meta: log_type
        value: ssh_accepted-password

  - grok:
      pattern: "^Accepted publickey for %{USERNAME:ssh_user} from %{IP:source_ip} port %{INT:source_port}"
      apply_on: message
    statics:
      - meta: log_type
        value: ssh_accepted-publickey

  - grok:
      pattern: "^Disconnected from (invalid user |authenticating user )?%{USERNAME:ssh_user} %{IP:source_ip} port %{INT:source_port}"
      apply_on: message
    statics:
      - meta: log_type
        value: ssh_disconnect

  # sudo
  - grok:
      pattern: "^%{USERNAME:sudo_user} : TTY=%{DATA:tty} ; PWD=%{DATA:pwd} ; USER=%{USERNAME:sudo_target_user} ; COMMAND=%{GREEDYDATA:sudo_command}$"
    statics:
      - meta: log_type
        value: sudo_success
```

Grok engine: `github.com/crowdsecurity/grokky` — wraps Go regexp with named patterns. RE2 via `github.com/wasilibs/go-re2` for performance.

### Stage s00-raw — RFC3164 syslog parser

`pkg/acquisition/modules/syslog/internal/parser/rfc3164/parse.go`

Hand-written byte scanner (no regex). Format: `<PRI>Mmm DD HH:MM:SS hostname program[pid]: message`. Extracts: PRI, Timestamp, Hostname, Tag, PID, Message. **Copy verbatim — MIT license, fastest possible syslog parser.**

---

## 3. Scenarios (Detection Rules)

`pkg/leakybucket/manager_load.go` — `BucketSpec`:

```go
type BucketSpec struct {
    Type                string         // "leaky" | "counter" | "trigger" | "conditional" | "bayesian"
    Name                string
    Filter              string         // expr: "evt.Meta.log_type == 'ssh_failed-password'"
    GroupBy             string         // expr: "evt.Meta.source_ip"
    Capacity            int            // burst (-1 = unlimited for counter)
    LeakSpeed           string         // "10s", "1m"
    Duration            string         // for counter type
    Blackhole           string         // suppress repeated alerts
    Distinct            string         // dedup expr within bucket
    Labels              map[string]any
    OverflowFilter      string
    ConditionalOverflow string
    CancelOnFilter      string
    Reprocess           bool
}
```

### SSH brute-force — `crowdsecurity/ssh-bf`

```yaml
type: leaky
name: crowdsecurity/ssh-bf
filter: "evt.Meta.log_type in ['ssh_failed-password', 'ssh_invalid-user']"
groupby: evt.Meta.source_ip
leakspeed: "10s"
capacity: 5
blackhole: 1m
labels:
  service: ssh
  classification:
    - attack.T1110
```

### SSH user enum — `crowdsecurity/ssh-bf_user-enum`

```yaml
type: leaky
filter: "evt.Meta.log_type == 'ssh_invalid-user'"
groupby: evt.Meta.source_ip
distinct: evt.Meta.ssh_user
leakspeed: "10s"
capacity: 5
```

### Port scan

```yaml
type: leaky
filter: "evt.Meta.log_type == 'iptables_drop'"
groupby: evt.Meta.source_ip
distinct: evt.Meta.dst_port
leakspeed: "10s"
capacity: 20
```

### Bucket types

`pkg/leakybucket/buckettype.go`:
- `leaky` — token bucket, overflows when rate exceeded
- `trigger` — immediate single-event alert
- `counter` — fixed time window count
- `conditional` — custom condition expression on queue
- `bayesian` — probabilistic scoring

---

## 4. Leaky-Bucket Algorithm

`pkg/leakybucket/bucket.go` — uses `golang.org/x/time/rate.Limiter`:

```
rate.NewLimiter(rate.Every(leakspeed), capacity)
```

- `leakspeed = 10s` → 1 token per 10s
- `capacity = 5` → bucket holds up to 5 tokens (burst)

`Limiter.Allow()`:
- `true` → fits, queue event
- `false` → bucket full, **overflow fires**

Each bucket runs as a goroutine (`LeakRoutine`):
- `In chan *pipeline.Event`
- `Out chan *pipeline.Queue`
- `Suicide chan bool`
- Duration ticker for timed expiry

vpsguard adaptation:

```go
import "golang.org/x/time/rate"

type SSHBruteForceDetector struct {
    limiters sync.Map  // map[string]*rate.Limiter per source IP
    capacity int
    period   time.Duration
}

func (d *SSHBruteForceDetector) RecordFailure(ip string) bool {
    v, _ := d.limiters.LoadOrStore(ip, rate.NewLimiter(rate.Every(d.period), d.capacity))
    return !v.(*rate.Limiter).Allow()  // true = overflow = alert
}
```

---

## 5. Go Libraries (from `go.mod`)

| Library | Purpose | vpsguard use |
|---------|---------|--------------|
| `github.com/nxadm/tail` | log file tail with rotation | file reading |
| `github.com/fsnotify/fsnotify` | inotify | new file detection |
| `golang.org/x/time/rate` | token bucket | brute-force detection |
| `github.com/crowdsecurity/grokky` | grok patterns | log parsing |
| `github.com/expr-lang/expr` | expression eval | filters |
| `github.com/sirupsen/logrus` | structured logs | internal logging |
| `gopkg.in/tomb.v2` | goroutine lifecycle | acquisition |
| `github.com/wasilibs/go-re2` | RE2 (no backtracking) | log parsing |
| `gopkg.in/yaml.v3` | YAML | config |
| `github.com/spf13/cobra` | CLI | commands |
| `github.com/coreos/go-systemd/v22` | journald | journalctl alt path |

---

## 6. Bouncer Concept

`config/profiles.yaml`:

```yaml
name: default_ip_remediation
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
  - type: ban
    duration: 4h
on_success: break
```

Engine detects → emits `RuntimeAlert` → notification plugin (`pkg/csplugin/`) sends to Slack/Telegram. Template format from `cmd/notification-slack/slack.yaml`:

```
{{range .}}{{range .Decisions}}{{.Value}} triggered {{.Scenario}}{{end}}{{end}}
```

---

## 7. vpsguard Top-15 Steal List

| # | What | Source | Why |
|---|------|--------|-----|
| 1 | File tail with rotation | `pkg/acquisition/modules/file/run.go` | Auth.log tailing |
| 2 | inotify dir watching | same file `monitorNewFiles()` | new files on rotate |
| 3 | Journald subprocess reader | `pkg/acquisition/modules/journalctl/run.go` | systemd journal |
| 4 | Token bucket rate limiter | `pkg/leakybucket/bucket.go` + `rate.Limiter` | SSH 20-in-5min |
| 5 | Bucket partitioning by IP | `pkg/leakybucket/manager_run.go` | per-IP detection |
| 6 | Tomb goroutine lifecycle | `pkg/acquisition/modules/file/run.go` | clean shutdown |
| 7 | RFC3164 syslog parser | `pkg/acquisition/modules/syslog/internal/parser/rfc3164/parse.go` | zero-regex, MIT |
| 8 | Pipeline Event struct | `pkg/pipeline/event.go` | data model |
| 9 | BucketSpec YAML schema | `pkg/leakybucket/manager_load.go` | declarative rules |
| 10 | Grok via grokky | `pkg/parser/grok.go` | named SSH patterns |
| 11 | Auto-detect SSH source | `config/detect.yaml:215-271` | distro-aware |
| 12 | Notification template | `cmd/notification-slack/slack.yaml` | Telegram format |
| 13 | Graceful ctx shutdown | `pkg/acquisition/modules/journalctl/run.go` | subprocess kill |
| 14 | Conditional bucket | `pkg/leakybucket/buckettype.go` | complex alerts |
| 15 | Blackhole suppression | `pkg/leakybucket/blackhole.go` | dedup Telegram |

---

## Pipeline Flow

```
Log Line (raw)
  ↓
Acquisition (file/journalctl) → pipeline.Line{Raw, Labels, Time}
  ↓
Stage s00-raw (syslog header) → event.Parsed{timestamp, hostname, program, message}
  ↓
Stage s01-parse (sshd grok) → event.Meta{log_type, source_ip, ssh_user}
  ↓
Stage s02-enrich (GeoIP, DNS) → event.Enriched{country, AS}
  ↓
Leaky Buckets → rate.Limiter.Allow() → overflow?
  ↓
RuntimeAlert → Notification (Telegram)
```
