package filewatch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
)

// Integration-style test: build a fake /home tree, run the detector,
// trigger writes, assert events.
func TestFilewatch_HomeUserKeys(t *testing.T) {
	dir := t.TempDir()
	homeRoot := filepath.Join(dir, "home")

	// Pre-create one user with an authorized_keys file.
	mustMkdir(t, filepath.Join(homeRoot, "alice", ".ssh"))
	mustWrite(t, filepath.Join(homeRoot, "alice", ".ssh", "authorized_keys"), "ssh-rsa A...")

	d := &Detector{
		Watches:  []watch{}, // disable system defaults so the test stays sandbox-pure
		HomeRoot: homeRoot,
	}

	out := make(chan *event.Event, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- d.Run(ctx, out) }()

	// Allow watcher setup. CI containers can be slow; be generous.
	time.Sleep(300 * time.Millisecond)

	// 1. Modify alice's existing key file.
	mustAppend(t, filepath.Join(homeRoot, "alice", ".ssh", "authorized_keys"), "\nssh-rsa B...\n")

	// 2. Create bob's home dir + .ssh + key after the fact.
	mustMkdir(t, filepath.Join(homeRoot, "bob", ".ssh"))
	// The dynamic discovery happens when the child of homeRoot is created
	// AND when fsnotify delivers the event. Give the watcher time to
	// register bob's path before we touch the key file.
	time.Sleep(400 * time.Millisecond)
	mustWrite(t, filepath.Join(homeRoot, "bob", ".ssh", "authorized_keys"), "ssh-rsa C...")
	// Keep nudging the file in case the watcher only just got the new path.
	for i := 0; i < 10; i++ {
		time.Sleep(200 * time.Millisecond)
		mustAppend(t, filepath.Join(homeRoot, "bob", ".ssh", "authorized_keys"), "\nssh-rsa D...\n")
	}

	deadline := time.After(8 * time.Second)
	got := map[string]bool{}
	for len(got) < 2 {
		select {
		case e := <-out:
			if user, _ := e.Fields["user"].(string); user != "" {
				got[user] = true
			}
		case <-deadline:
			t.Fatalf("timeout: got users=%v", got)
		}
	}

	if !got["alice"] {
		t.Error("missing event for alice")
	}
	if !got["bob"] {
		t.Error("missing event for bob (dynamic discovery failed)")
	}

	cancel()
	<-done
}

func TestUserFromPath(t *testing.T) {
	cases := []struct {
		path, homeRoot, want string
	}{
		{"/home/alice/.ssh/authorized_keys", "/home", "alice"},
		{"/home/alice", "/home", "alice"},
		{"/root/.ssh/authorized_keys", "/home", "root"},
		{"/etc/passwd", "/home", ""},
		{"/var/spool/cron/alice", "/home", ""},
	}
	for _, c := range cases {
		got := userFromPath(c.path, c.homeRoot)
		if got != c.want {
			t.Errorf("userFromPath(%q,%q) = %q, want %q", c.path, c.homeRoot, got, c.want)
		}
	}
}

func TestIsHomeChild(t *testing.T) {
	if !isHomeChild("/home/alice", "/home") {
		t.Error("/home/alice should be home child")
	}
	if isHomeChild("/home/alice/.ssh", "/home") {
		t.Error("/home/alice/.ssh should NOT be direct home child")
	}
	if isHomeChild("/root", "/home") {
		t.Error("/root is not under /home")
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}
func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
func mustAppend(t *testing.T, p, body string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(body); err != nil {
		t.Fatal(err)
	}
}
