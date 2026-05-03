// Package fim performs lightweight file integrity monitoring for critical VPS
// files. It baselines at startup and reports later hash/stat changes.
package fim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
	"github.com/fsnotify/fsnotify"
)

const Name = "fim"

type Detector struct {
	Paths     []string
	Interval  time.Duration
	StatePath string
}

type snap struct {
	hash string
	size int64
	mode os.FileMode
}

var defaultPaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/sudoers",
	"/etc/ssh/sshd_config",
	"/etc/pam.d/common-auth",
	"/etc/pam.d/sshd",
	"/etc/ld.so.preload",
	"/etc/crontab",
}

func (d *Detector) Name() string { return Name }

func (d *Detector) Run(ctx context.Context, out chan<- *event.Event) error {
	paths := d.Paths
	if len(paths) == 0 {
		paths = defaultPaths
	}
	interval := d.Interval
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	store, err := openStore(d.StatePath)
	if err != nil {
		out <- event.New(event.TypeAgentError, event.SevMedium, "FIM baseline persistence unavailable").
			WithSource(Name).
			WithMessage(err.Error()).
			WithField("state_path", d.StatePath)
	}
	if store != nil {
		defer store.Close()
	}
	base := baseline(paths, store)
	checkSSHD(out)
	watcher, _ := fsnotify.NewWatcher()
	if watcher != nil {
		defer watcher.Close()
		for _, p := range paths {
			_ = watcher.Add(p)
		}
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-watchEvents(watcher):
			if ev.Name != "" {
				check([]string{ev.Name}, base, store, out)
			}
		case <-t.C:
			check(paths, base, store, out)
		}
	}
}

func watchEvents(w *fsnotify.Watcher) <-chan fsnotify.Event {
	if w == nil {
		return nil
	}
	return w.Events
}

func baseline(paths []string, store *store) map[string]snap {
	out := map[string]snap{}
	if store != nil {
		out = store.LoadAll()
	}
	for _, p := range paths {
		if _, ok := out[p]; ok {
			continue
		}
		s, err := snapshot(p)
		if err == nil {
			out[p] = s
			if store != nil {
				_ = store.Put(p, s)
			}
		}
	}
	return out
}

func check(paths []string, base map[string]snap, store *store, out chan<- *event.Event) {
	for _, p := range paths {
		cur, err := snapshot(p)
		old, existed := base[p]
		if err != nil {
			if existed && errors.Is(err, os.ErrNotExist) {
				delete(base, p)
				if store != nil {
					_ = store.Delete(p)
				}
				out <- event.New(event.TypeFIMModified, event.SevHigh, "Sensitive file deleted").
					WithSource(Name).WithField("path", p).WithField("change", "deleted")
			}
			continue
		}
		if !existed {
			base[p] = cur
			if store != nil {
				_ = store.Put(p, cur)
			}
			out <- event.New(event.TypeFIMModified, event.SevHigh, "Sensitive file created").
				WithSource(Name).WithField("path", p).WithField("change", "created")
			continue
		}
		if cur != old {
			base[p] = cur
			if store != nil {
				_ = store.Put(p, cur)
			}
			out <- event.New(event.TypeFIMModified, event.SevHigh, "Sensitive file modified").
				WithSource(Name).
				WithField("path", p).
				WithField("change", "modified").
				WithField("old_hash", old.hash).
				WithField("new_hash", cur.hash).
				WithField("old_size", old.size).
				WithField("new_size", cur.size).
				WithField("old_mode", old.mode.String()).
				WithField("new_mode", cur.mode.String())
		}
	}
}

func defaultStatePath() string {
	return filepath.Join("/var/lib/vpsguard", "fim.db")
}

func snapshot(path string) (snap, error) {
	info, err := os.Stat(path)
	if err != nil {
		return snap{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return snap{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return snap{}, err
	}
	return snap{hash: hex.EncodeToString(h.Sum(nil)), size: info.Size(), mode: info.Mode()}, nil
}

func checkSSHD(out chan<- *event.Event) {
	b, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		clean := strings.TrimSpace(line)
		if clean == "" || strings.HasPrefix(clean, "#") {
			continue
		}
		fields := strings.Fields(strings.ToLower(clean))
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "permitrootlogin" && (fields[1] == "yes" || fields[1] == "without-password" || fields[1] == "prohibit-password") {
			out <- event.New(event.TypeFIMModified, event.SevMedium, "sshd permits root login").
				WithSource(Name).
				WithField("path", "/etc/ssh/sshd_config").
				WithField("setting", "PermitRootLogin").
				WithField("value", fields[1])
		}
		if fields[0] == "passwordauthentication" && fields[1] == "yes" {
			out <- event.New(event.TypeFIMModified, event.SevMedium, "sshd allows password authentication").
				WithSource(Name).
				WithField("path", "/etc/ssh/sshd_config").
				WithField("setting", "PasswordAuthentication").
				WithField("value", fields[1])
		}
	}
}
