// Package correlate observes detector events and emits derived events
// based on cross-event patterns. It is the brain that turns raw signals
// (a single failed SSH login, a single new IP) into the alerts that
// actually matter (brute force attack from this IP, login after a burst
// of failures, login from a never-before-seen address).
//
// State is in-memory only by design — restarts lose the sliding-window
// counters. The known-IP set is the one piece persisted to disk.
package correlate

import (
	"fmt"
	"sync"
	"time"

	"github.com/ceorkm/vpsguard/internal/config"
	"github.com/ceorkm/vpsguard/internal/event"
)

// Tunables — exposed as fields on Correlator so tests can poke them.
const (
	defaultBurstWindow      = 5 * time.Minute
	defaultEnumWindow       = 10 * time.Minute
	defaultBurstThreshold   = 20
	defaultEnumThreshold    = 5
	defaultTotalWindow      = 10 * time.Minute
	defaultTotalThreshold   = 50
	defaultPostFailWindow   = 10 * time.Minute
	defaultPostFailMinFails = 5

	// Reinfection-loop tunables. Default: same exe respawning ≥3 times
	// in 30 min triggers ONE process.reinfection_loop alert and then
	// silences per-PID alerts for that exe for 6 hours.
	defaultReinfectWindow    = 30 * time.Minute
	defaultReinfectThreshold = 3
	defaultReinfectMute      = 6 * time.Hour
)

// Now is overridable in tests.
var Now = time.Now

type Correlator struct {
	cfg   *config.Config
	known KnownIPs

	BurstWindow      time.Duration
	EnumWindow       time.Duration
	BurstThreshold   int
	EnumThreshold    int
	TotalWindow      time.Duration
	TotalThreshold   int
	PostFailWindow   time.Duration
	PostFailMinFails int

	ReinfectWindow    time.Duration
	ReinfectThreshold int
	ReinfectMute      time.Duration

	mu            sync.Mutex
	ipState       map[string]*ipState
	bruteSent     map[string]time.Time // suppress repeat brute-force alerts per IP for window
	total         totalState
	incidents     map[string]*incidentState
	nextIncident  int
	reinfectState map[string]*reinfectionState
}

// reinfectionState tracks how often a single executable has been seen
// triggering a process-class alert. Used to recognise watchdog-style
// implants that get re-dropped from cron / systemd / .bashrc and would
// otherwise spam the user with a fresh Telegram alert per re-spawn.
type reinfectionState struct {
	times     []time.Time
	alertedAt time.Time
}

// KnownIPs persists the set of IPs that have ever logged in successfully.
// First-seen tracking is the cheapest possible "is this attacker familiar"
// signal; failed logins do not count (they happen from random IPs all day).
type KnownIPs interface {
	Has(ip string) bool
	Add(ip string)
}

type ipState struct {
	failures []time.Time            // timestamps within BurstWindow
	users    map[string][]time.Time // username -> recent attempt times (within EnumWindow)
}

type totalState struct {
	failures []time.Time
	sentAt   time.Time
}

type incidentState struct {
	id       string
	lastSeen time.Time
}

func New(cfg *config.Config, known KnownIPs) *Correlator {
	return &Correlator{
		cfg:              cfg,
		known:            known,
		BurstWindow:      defaultBurstWindow,
		EnumWindow:       defaultEnumWindow,
		BurstThreshold:   defaultBurstThreshold,
		EnumThreshold:    defaultEnumThreshold,
		TotalWindow:      defaultTotalWindow,
		TotalThreshold:   defaultTotalThreshold,
		PostFailWindow:    defaultPostFailWindow,
		PostFailMinFails:  defaultPostFailMinFails,
		ReinfectWindow:    defaultReinfectWindow,
		ReinfectThreshold: defaultReinfectThreshold,
		ReinfectMute:      defaultReinfectMute,
		ipState:           map[string]*ipState{},
		bruteSent:         map[string]time.Time{},
		incidents:         map[string]*incidentState{},
		reinfectState:     map[string]*reinfectionState{},
	}
}

// Process consumes one event and returns the same event plus any derived
// alerts. The original event is always passed through (potentially with
// severity adjusted).
func (c *Correlator) Process(e *event.Event) []*event.Event {
	if e == nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	out := []*event.Event{e}

	switch e.Type {
	case event.TypeSSHLoginFailed, event.TypeSSHInvalidUser:
		c.recordFailure(e)
		if alert := c.checkBruteForce(e); alert != nil {
			out = append(out, alert)
		}
		if alert := c.checkTotalFailures(e); alert != nil {
			out = append(out, alert)
		}
	case event.TypeSSHLoginSuccess:
		// 1. Suppress / downgrade if from a trusted IP.
		// 2. Upgrade root/password logins because they are high-risk even
		//    before the first-seen logic runs.
		// 3. Upgrade to high + add first_seen=true if IP is new.
		// 4. Emit ssh.login.after_failures if recent failure burst from this IP.
		ip := stringField(e, "ip")
		if ip != "" && c.cfg != nil && c.cfg.IsTrusted(ip) {
			e.Severity = event.SevLow
			e.WithField("trusted", true)
		} else {
			if stringField(e, "user") == "root" {
				e.Severity = maxSeverity(e.Severity, event.SevHigh)
				e.WithField("root_login", true)
			}
			if stringField(e, "method") == "password" {
				e.Severity = maxSeverity(e.Severity, event.SevHigh)
				e.WithField("password_login", true)
			}
			if ip != "" && c.known != nil && !c.known.Has(ip) {
				e.Severity = maxSeverity(e.Severity, event.SevHigh)
				e.WithField("first_seen", true)
			}
		}
		if ip != "" && c.known != nil {
			c.known.Add(ip)
		}
		if alert := c.checkSuccessAfterFailures(e); alert != nil {
			out = append(out, alert)
		}
	case event.TypeProcessSuspicious, event.TypeProcessTmpOutbound,
		event.TypeProcessKnownMiner, event.TypeProcessHighCPU,
		event.TypeProcessWebShell, event.TypeProcessCredAccess,
		event.TypeProcessEnvTamper:
		// Reinfection-loop detection. The same executable getting flagged
		// again and again typically means a cron / systemd / .bashrc
		// payload keeps re-spawning it. We want ONE escalated alert,
		// not a Telegram message every 5 minutes.
		if alert, suppress := c.checkReinfection(e); suppress {
			return nil
		} else if alert != nil {
			out = append(out, alert)
		}
	}
	for _, produced := range out {
		c.attachIncident(produced)
	}
	return out
}

// checkReinfection updates the per-exe respawn counter for a process
// event. If the threshold is hit it returns the synthesized
// reinfection_loop alert. If we're already inside the post-alert mute
// window it returns suppress=true so the caller drops the event entirely.
func (c *Correlator) checkReinfection(e *event.Event) (alert *event.Event, suppress bool) {
	exe := stringField(e, "exe")
	if exe == "" {
		return nil, false
	}
	st := c.reinfectState[exe]
	if st == nil {
		st = &reinfectionState{}
		c.reinfectState[exe] = st
	}
	now := Now()

	// Already alerted recently → suppress further per-PID noise.
	if !st.alertedAt.IsZero() && now.Sub(st.alertedAt) < c.ReinfectMute {
		return nil, true
	}

	// Trim, append, and decide.
	cutoff := now.Add(-c.ReinfectWindow)
	st.times = trimBefore(st.times, cutoff)
	st.times = append(st.times, now)

	if len(st.times) < c.ReinfectThreshold {
		return nil, false
	}

	st.alertedAt = now
	count := len(st.times)
	return event.New(event.TypeProcessReinfection, event.SevCritical,
			"Process keeps respawning — reinfection loop detected").
			WithSource("correlator").
			WithMessage(fmt.Sprintf(
				"the same executable has been flagged %d times within %s — likely watchdog-style persistence (cron, systemd, ~/.bashrc, or a parent service)",
				count, c.ReinfectWindow)).
			WithField("exe", exe).
			WithField("count", count).
			WithField("window", c.ReinfectWindow.String()).
			WithField("mute", c.ReinfectMute.String()).
			WithField("recommended", "find the source: ls -la /etc/cron.d/ /etc/cron.hourly/ /var/spool/cron/ /etc/systemd/system/ ~/.bashrc"),
		false
}

func maxSeverity(a, b event.Severity) event.Severity {
	if config.SeverityRank(b) > config.SeverityRank(a) {
		return b
	}
	return a
}

func (c *Correlator) recordFailure(e *event.Event) {
	ip := stringField(e, "ip")
	if ip == "" {
		return
	}
	now := Now()
	st := c.ipState[ip]
	if st == nil {
		st = &ipState{users: map[string][]time.Time{}}
		c.ipState[ip] = st
	}
	st.failures = append(st.failures, now)
	c.total.failures = append(c.total.failures, now)

	// Trim failures older than BurstWindow.
	cutoffBurst := now.Add(-c.BurstWindow)
	st.failures = trimBefore(st.failures, cutoffBurst)
	c.total.failures = trimBefore(c.total.failures, now.Add(-c.TotalWindow))

	// Trim per-user windows older than EnumWindow.
	cutoffEnum := now.Add(-c.EnumWindow)
	if user := stringField(e, "user"); user != "" {
		st.users[user] = append(st.users[user], now)
		st.users[user] = trimBefore(st.users[user], cutoffEnum)
	}
	// Drop users whose entire window is empty.
	for u, ts := range st.users {
		if len(ts) == 0 {
			delete(st.users, u)
		}
	}
}

func (c *Correlator) checkTotalFailures(e *event.Event) *event.Event {
	if c.TotalThreshold <= 0 {
		return nil
	}
	now := Now()
	if !c.total.sentAt.IsZero() && now.Sub(c.total.sentAt) < c.TotalWindow {
		return nil
	}
	failedCount := len(c.total.failures)
	if failedCount < c.TotalThreshold {
		return nil
	}
	c.total.sentAt = now
	return event.New(event.TypeSSHBruteforce, event.SevHigh,
		"SSH brute-force storm detected").
		WithSource("correlator").
		WithMessage("many failed SSH attempts hit this server within a short window").
		WithField("failed_attempts", failedCount).
		WithField("window", c.TotalWindow.String()).
		WithField("reason", "total_failure_storm")
}

func (c *Correlator) checkBruteForce(e *event.Event) *event.Event {
	ip := stringField(e, "ip")
	st := c.ipState[ip]
	if st == nil {
		return nil
	}

	// Don't re-alert on the same IP within the burst window.
	if last, ok := c.bruteSent[ip]; ok && Now().Sub(last) < c.BurstWindow {
		return nil
	}

	failedCount := len(st.failures)
	distinctUsers := len(st.users)

	switch {
	case failedCount >= c.BurstThreshold:
		c.bruteSent[ip] = Now()
		return event.New(event.TypeSSHBruteforce, event.SevHigh,
			"SSH brute-force attack detected").
			WithSource("correlator").
			WithMessage("repeated failed SSH attempts from a single source IP within a short window").
			WithField("ip", ip).
			WithField("failed_attempts", failedCount).
			WithField("distinct_users", distinctUsers).
			WithField("window", c.BurstWindow.String()).
			WithField("reason", "failure_burst")
	case distinctUsers >= c.EnumThreshold:
		c.bruteSent[ip] = Now()
		users := make([]string, 0, len(st.users))
		for u := range st.users {
			users = append(users, u)
		}
		return event.New(event.TypeSSHBruteforce, event.SevHigh,
			"SSH user enumeration detected").
			WithSource("correlator").
			WithMessage("attempts to many distinct usernames from a single source IP").
			WithField("ip", ip).
			WithField("distinct_users", distinctUsers).
			WithField("usernames_sample", users).
			WithField("window", c.EnumWindow.String()).
			WithField("reason", "user_enumeration")
	}
	return nil
}

func (c *Correlator) checkSuccessAfterFailures(e *event.Event) *event.Event {
	ip := stringField(e, "ip")
	if ip == "" {
		return nil
	}
	st := c.ipState[ip]
	if st == nil {
		return nil
	}

	// Trim failures older than PostFailWindow before counting.
	cutoff := Now().Add(-c.PostFailWindow)
	recent := trimBefore(st.failures, cutoff)
	if len(recent) < c.PostFailMinFails {
		return nil
	}
	user := stringField(e, "user")
	return event.New(event.TypeSSHLoginAfterFails, event.SevCritical,
		"SSH login succeeded after failed-attempt burst").
		WithSource("correlator").
		WithMessage("a successful login arrived from an IP that just produced multiple failed attempts — possible compromise").
		WithField("ip", ip).
		WithField("user", user).
		WithField("recent_failures", len(recent)).
		WithField("window", c.PostFailWindow.String())
}

func stringField(e *event.Event, key string) string {
	if e == nil || e.Fields == nil {
		return ""
	}
	v, ok := e.Fields[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func trimBefore(ts []time.Time, cutoff time.Time) []time.Time {
	// Filter in-place; ts is short (max BurstThreshold-ish).
	out := ts[:0]
	for _, t := range ts {
		if !t.Before(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

func (c *Correlator) attachIncident(e *event.Event) {
	if e == nil || e.Severity == event.SevInfo || e.Severity == event.SevLow {
		return
	}
	key := incidentKey(e)
	if key == "" {
		return
	}
	now := Now()
	for k, st := range c.incidents {
		if now.Sub(st.lastSeen) > 10*time.Minute {
			delete(c.incidents, k)
		}
	}
	st := c.incidents[key]
	if st == nil {
		c.nextIncident++
		st = &incidentState{id: fmt.Sprintf("inc-%06d", c.nextIncident)}
		c.incidents[key] = st
	}
	st.lastSeen = now
	e.WithField("incident_id", st.id).
		WithField("incident_key", key).
		WithField("incident_window", "10m0s")
}

func incidentKey(e *event.Event) string {
	if ip := anyField(e, "ip"); ip != "" {
		return "ip:" + ip
	}
	if exe := anyField(e, "exe"); exe != "" {
		return "exe:" + exe
	}
	if path := anyField(e, "path"); path != "" {
		return "path:" + path
	}
	if e.Source != "" {
		return "source:" + e.Source
	}
	return ""
}

func anyField(e *event.Event, key string) string {
	if e == nil || e.Fields == nil {
		return ""
	}
	if v, ok := e.Fields[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}
