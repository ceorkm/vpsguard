package correlate

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ceorkm/vpsguard/internal/config"
	"github.com/ceorkm/vpsguard/internal/event"
)

// withTime overrides Now() inside a test, returning a cleanup function.
func withTime(t *testing.T, fixed time.Time) (func(d time.Duration), func()) {
	t.Helper()
	current := fixed
	Now = func() time.Time { return current }
	advance := func(d time.Duration) { current = current.Add(d) }
	cleanup := func() { Now = time.Now }
	return advance, cleanup
}

func failedEvent(ip, user string) *event.Event {
	return event.New(event.TypeSSHLoginFailed, event.SevLow, "SSH login failed").
		WithSource("ssh").
		WithField("ip", ip).
		WithField("user", user)
}

func successEvent(ip, user string) *event.Event {
	return event.New(event.TypeSSHLoginSuccess, event.SevMedium, "SSH login (publickey)").
		WithSource("ssh").
		WithField("ip", ip).
		WithField("user", user)
}

func passwordSuccessEvent(ip, user string) *event.Event {
	return event.New(event.TypeSSHLoginSuccess, event.SevMedium, "SSH login (password)").
		WithSource("ssh").
		WithField("ip", ip).
		WithField("user", user).
		WithField("method", "password")
}

func mustCfg(t *testing.T, trusted []string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	body := "trusted_ips:\n"
	for _, ip := range trusted {
		body += "  - " + ip + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestProcess_PassesEventThrough(t *testing.T) {
	c := New(nil, NewMemoryKnownIPs())
	in := event.New(event.TypeAgentHeartbeat, event.SevInfo, "tick")
	out := c.Process(in)
	if len(out) != 1 || out[0] != in {
		t.Errorf("expected passthrough, got %+v", out)
	}
}

func TestProcess_NilEvent(t *testing.T) {
	c := New(nil, NewMemoryKnownIPs())
	if got := c.Process(nil); got != nil {
		t.Errorf("nil event should return nil, got %+v", got)
	}
}

func TestBruteForce_FailureBurst(t *testing.T) {
	advance, cleanup := withTime(t, time.Date(2026, 5, 2, 21, 0, 0, 0, time.UTC))
	defer cleanup()

	c := New(nil, NewMemoryKnownIPs())
	c.BurstThreshold = 5
	c.BurstWindow = 1 * time.Minute

	for i := 0; i < 4; i++ {
		out := c.Process(failedEvent("1.2.3.4", "admin"))
		if len(out) != 1 {
			t.Fatalf("attempt %d: expected only original event, got %d", i, len(out))
		}
		advance(5 * time.Second)
	}
	// 5th failure crosses threshold.
	out := c.Process(failedEvent("1.2.3.4", "admin"))
	if len(out) != 2 {
		t.Fatalf("expected 2 events (failure + bruteforce), got %d", len(out))
	}
	if out[1].Type != event.TypeSSHBruteforce {
		t.Errorf("derived event type: %q", out[1].Type)
	}
	if reason, _ := out[1].Fields["reason"].(string); reason != "failure_burst" {
		t.Errorf("expected reason failure_burst, got %q", reason)
	}
}

func TestBruteForce_UserEnumeration(t *testing.T) {
	advance, cleanup := withTime(t, time.Date(2026, 5, 2, 21, 0, 0, 0, time.UTC))
	defer cleanup()

	c := New(nil, NewMemoryKnownIPs())
	c.BurstThreshold = 1000 // disable failure-burst path
	c.EnumThreshold = 5
	c.EnumWindow = 10 * time.Minute

	users := []string{"root", "admin", "ubuntu", "ftp", "oracle"}
	var alerts []*event.Event
	for _, u := range users {
		out := c.Process(failedEvent("1.2.3.4", u))
		alerts = append(alerts, out[1:]...)
		advance(10 * time.Second)
	}
	// One enumeration alert expected after the 5th distinct user.
	if len(alerts) != 1 {
		t.Fatalf("expected 1 enum alert, got %d (alerts=%+v)", len(alerts), alerts)
	}
	if reason, _ := alerts[0].Fields["reason"].(string); reason != "user_enumeration" {
		t.Errorf("expected reason user_enumeration, got %q", reason)
	}
	if d, _ := alerts[0].Fields["distinct_users"].(int); d != 5 {
		t.Errorf("distinct_users: %d", d)
	}
}

func TestBruteForce_TotalFailureStorm(t *testing.T) {
	advance, cleanup := withTime(t, time.Date(2026, 5, 2, 21, 0, 0, 0, time.UTC))
	defer cleanup()

	c := New(nil, NewMemoryKnownIPs())
	c.BurstThreshold = 1000 // isolate total-failure path
	c.EnumThreshold = 1000
	c.TotalThreshold = 5
	c.TotalWindow = 10 * time.Minute

	var alerts []*event.Event
	for i := 0; i < 5; i++ {
		ip := "1.2.3." + string(rune('1'+i))
		out := c.Process(failedEvent(ip, "root"))
		alerts = append(alerts, out[1:]...)
		advance(10 * time.Second)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 total storm alert, got %d", len(alerts))
	}
	if reason, _ := alerts[0].Fields["reason"].(string); reason != "total_failure_storm" {
		t.Errorf("expected total_failure_storm reason, got %q", reason)
	}
}

func TestBruteForce_SuppressionWithinWindow(t *testing.T) {
	advance, cleanup := withTime(t, time.Date(2026, 5, 2, 21, 0, 0, 0, time.UTC))
	defer cleanup()

	c := New(nil, NewMemoryKnownIPs())
	c.BurstThreshold = 3
	c.BurstWindow = 1 * time.Minute

	// First burst -> alert.
	for i := 0; i < 3; i++ {
		c.Process(failedEvent("1.2.3.4", "u"))
		advance(5 * time.Second)
	}
	// Subsequent failures within window must NOT re-alert.
	out := c.Process(failedEvent("1.2.3.4", "u"))
	if len(out) != 1 {
		t.Errorf("expected suppression within window, got %d events", len(out))
	}
}

func TestSuccessAfterFailures(t *testing.T) {
	advance, cleanup := withTime(t, time.Date(2026, 5, 2, 21, 0, 0, 0, time.UTC))
	defer cleanup()

	c := New(nil, NewMemoryKnownIPs())
	c.BurstThreshold = 100 // disable bruteforce alert
	c.PostFailMinFails = 3
	c.PostFailWindow = 5 * time.Minute

	// 4 failures from same IP.
	for i := 0; i < 4; i++ {
		c.Process(failedEvent("1.2.3.4", "admin"))
		advance(10 * time.Second)
	}
	// Now a success arrives — must produce after_failures alert.
	out := c.Process(successEvent("1.2.3.4", "admin"))
	if len(out) != 2 {
		t.Fatalf("expected 2 events, got %d", len(out))
	}
	if out[1].Type != event.TypeSSHLoginAfterFails {
		t.Errorf("derived type: %q", out[1].Type)
	}
	if out[1].Severity != event.SevCritical {
		t.Errorf("severity: %q", out[1].Severity)
	}
	if rf, _ := out[1].Fields["recent_failures"].(int); rf != 4 {
		t.Errorf("recent_failures: %d", rf)
	}
}

func TestSuccessAfterFailures_NotEnoughFailures(t *testing.T) {
	c := New(nil, NewMemoryKnownIPs())
	c.PostFailMinFails = 5
	for i := 0; i < 2; i++ {
		c.Process(failedEvent("1.2.3.4", "x"))
	}
	out := c.Process(successEvent("1.2.3.4", "x"))
	if len(out) != 1 {
		t.Errorf("only 2 failures, no derived alert expected; got %d", len(out))
	}
}

func TestTrustedIP_DowngradesSuccess(t *testing.T) {
	cfg := mustCfg(t, []string{"102.89.34.0/24"})
	c := New(cfg, NewMemoryKnownIPs())

	out := c.Process(successEvent("102.89.34.12", "ubuntu"))
	if out[0].Severity != event.SevLow {
		t.Errorf("expected severity downgraded to low, got %q", out[0].Severity)
	}
	if v, _ := out[0].Fields["trusted"].(bool); !v {
		t.Error("expected trusted=true field")
	}
}

func TestFirstSeenIP_UpgradesSuccess(t *testing.T) {
	known := NewMemoryKnownIPs()
	c := New(nil, known)

	out := c.Process(successEvent("8.8.8.8", "root"))
	if out[0].Severity != event.SevHigh {
		t.Errorf("expected first-seen success severity high, got %q", out[0].Severity)
	}
	if v, _ := out[0].Fields["first_seen"].(bool); !v {
		t.Error("expected first_seen=true field")
	}
	// Subsequent success from same IP must NOT be upgraded.
	out2 := c.Process(successEvent("8.8.8.8", "root"))
	if v, _ := out2[0].Fields["first_seen"].(bool); v {
		t.Error("second login should not have first_seen=true")
	}
}

func TestRootLogin_UpgradesSuccess(t *testing.T) {
	known := NewMemoryKnownIPs()
	known.Add("8.8.8.8")
	c := New(nil, known)

	out := c.Process(successEvent("8.8.8.8", "root"))
	if out[0].Severity != event.SevHigh {
		t.Errorf("expected root login severity high, got %q", out[0].Severity)
	}
	if v, _ := out[0].Fields["root_login"].(bool); !v {
		t.Error("expected root_login=true field")
	}
}

func TestPasswordLogin_UpgradesSuccess(t *testing.T) {
	known := NewMemoryKnownIPs()
	known.Add("8.8.8.8")
	c := New(nil, known)

	out := c.Process(passwordSuccessEvent("8.8.8.8", "ubuntu"))
	if out[0].Severity != event.SevHigh {
		t.Errorf("expected password login severity high, got %q", out[0].Severity)
	}
	if v, _ := out[0].Fields["password_login"].(bool); !v {
		t.Error("expected password_login=true field")
	}
}

func TestIncidentGrouping_SameActorWithinWindow(t *testing.T) {
	advance, cleanup := withTime(t, time.Date(2026, 5, 2, 21, 0, 0, 0, time.UTC))
	defer cleanup()

	c := New(nil, NewMemoryKnownIPs())
	first := c.Process(successEvent("8.8.8.8", "root"))[0]
	advance(2 * time.Minute)
	second := c.Process(successEvent("8.8.8.8", "root"))[0]

	id1, _ := first.Fields["incident_id"].(string)
	id2, _ := second.Fields["incident_id"].(string)
	if id1 == "" || id2 == "" {
		t.Fatalf("expected incident IDs, got %q and %q", id1, id2)
	}
	if id1 != id2 {
		t.Fatalf("same actor within window should reuse incident id: %q != %q", id1, id2)
	}
}

func TestIncidentGrouping_NewWindowGetsNewID(t *testing.T) {
	advance, cleanup := withTime(t, time.Date(2026, 5, 2, 21, 0, 0, 0, time.UTC))
	defer cleanup()

	c := New(nil, NewMemoryKnownIPs())
	first := c.Process(successEvent("8.8.8.8", "root"))[0]
	advance(11 * time.Minute)
	second := c.Process(successEvent("8.8.8.8", "root"))[0]

	id1, _ := first.Fields["incident_id"].(string)
	id2, _ := second.Fields["incident_id"].(string)
	if id1 == "" || id2 == "" {
		t.Fatalf("expected incident IDs, got %q and %q", id1, id2)
	}
	if id1 == id2 {
		t.Fatalf("new window should get a fresh incident id: %q", id1)
	}
}

func TestKnownIPs_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_ips.json")

	k1, err := NewFileKnownIPs(path)
	if err != nil {
		t.Fatal(err)
	}
	k1.Add("1.2.3.4")
	k1.Add("8.8.8.8")
	k1.Add("8.8.8.8") // dup

	// Reload from disk.
	k2, err := NewFileKnownIPs(path)
	if err != nil {
		t.Fatal(err)
	}
	if !k2.Has("1.2.3.4") || !k2.Has("8.8.8.8") {
		t.Errorf("persistence round-trip failed")
	}
	if k2.Has("9.9.9.9") {
		t.Errorf("unknown IP returned has=true")
	}
}

func TestKnownIPs_EmptyPathDisablesPersistence(t *testing.T) {
	k, err := NewFileKnownIPs("")
	if err != nil {
		t.Fatal(err)
	}
	k.Add("1.2.3.4")
	if !k.Has("1.2.3.4") {
		t.Error("in-memory add should still work with empty path")
	}
}
