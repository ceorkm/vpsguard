// Package filewatch watches sensitive Linux paths via inotify and emits
// events when they change. Top persistence vectors per the PRD.
package filewatch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/ceorkm/vpsguard/internal/event"
	"github.com/fsnotify/fsnotify"
)

const Name = "filewatch"

// watch describes a path to monitor and how to classify changes there.
type watch struct {
	path     string
	typ      string
	severity event.Severity
	title    string
	message  string
}

// Default watch list. PRD section 10.6–10.9.
var defaults = []watch{
	// Cron
	{path: "/etc/crontab", typ: event.TypeCronModified, severity: event.SevHigh, title: "Cron file modified", message: "/etc/crontab was modified — common attacker persistence vector"},
	{path: "/etc/cron.d", typ: event.TypeCronModified, severity: event.SevHigh, title: "Cron drop-in directory changed", message: "a file under /etc/cron.d was added or modified"},
	{path: "/etc/cron.hourly", typ: event.TypeCronModified, severity: event.SevHigh, title: "Hourly cron changed"},
	{path: "/etc/cron.daily", typ: event.TypeCronModified, severity: event.SevHigh, title: "Daily cron changed"},
	{path: "/etc/cron.weekly", typ: event.TypeCronModified, severity: event.SevMedium, title: "Weekly cron changed"},
	{path: "/etc/cron.monthly", typ: event.TypeCronModified, severity: event.SevMedium, title: "Monthly cron changed"},
	{path: "/var/spool/cron", typ: event.TypeCronModified, severity: event.SevHigh, title: "User crontab changed"},
	{path: "/var/spool/cron/crontabs", typ: event.TypeCronModified, severity: event.SevHigh, title: "User crontab changed"},

	// Sudoers
	{path: "/etc/sudoers", typ: event.TypeSudoerModified, severity: event.SevCritical, title: "Sudoers file modified", message: "/etc/sudoers was changed — privilege grants may have been altered"},
	{path: "/etc/sudoers.d", typ: event.TypeSudoerModified, severity: event.SevCritical, title: "Sudoers drop-in changed"},

	// Identity
	{path: "/etc/passwd", typ: event.TypeUserCreated, severity: event.SevHigh, title: "/etc/passwd modified", message: "user accounts may have been added or removed"},
	{path: "/etc/shadow", typ: event.TypeUserCreated, severity: event.SevHigh, title: "/etc/shadow modified"},
	{path: "/etc/group", typ: event.TypeUserCreated, severity: event.SevMedium, title: "/etc/group modified"},

	// SSH keys (root)
	{path: "/root/.ssh/authorized_keys", typ: event.TypeSSHKeyAdded, severity: event.SevCritical, title: "Root authorized_keys modified", message: "a new SSH key may grant attacker persistent access"},
	{path: "/root/.ssh", typ: event.TypeSSHKeyAdded, severity: event.SevHigh, title: "Root .ssh directory changed"},

	// Systemd
	{path: "/etc/systemd/system", typ: event.TypeSystemdServiceAdded, severity: event.SevHigh, title: "Systemd unit changed", message: "an attacker-installed service is a common persistence mechanism"},

	// Linker / shell init (high-impact persistence)
	{path: "/etc/ld.so.preload", typ: event.TypeSystemdServiceAdded, severity: event.SevCritical, title: "/etc/ld.so.preload modified", message: "ld.so.preload is a classic linker-rootkit persistence path"},
	{path: "/etc/profile", typ: event.TypeSystemdServiceAdded, severity: event.SevMedium, title: "/etc/profile modified"},
	{path: "/etc/bash.bashrc", typ: event.TypeSystemdServiceAdded, severity: event.SevMedium, title: "/etc/bash.bashrc modified"},
}

type Detector struct {
	// Optional override; if nil, defaults is used.
	Watches []watch

	// HomeRoot is the parent dir to scan for per-user authorized_keys.
	// Defaults to /home. Tests can point this at a fixture dir.
	HomeRoot string
}

func (d *Detector) Name() string { return Name }

func (d *Detector) Run(ctx context.Context, out chan<- *event.Event) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()

	watches := d.Watches
	if watches == nil {
		watches = defaults
	}
	homeRoot := d.HomeRoot
	if homeRoot == "" {
		homeRoot = "/home"
	}

	index := map[string]watch{}
	for _, wt := range watches {
		index[wt.path] = wt
		if err := w.Add(wt.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			parent := filepath.Dir(wt.path)
			if _, ok := index[parent]; !ok {
				_ = w.Add(parent)
			}
		}
	}

	// Per-user authorized_keys discovery. Add every existing
	// /home/<user>/.ssh/authorized_keys as an explicit watch, then watch
	// /home itself for new user dirs (we add their keys when they appear).
	addUserKeys(w, index, homeRoot)
	if err := w.Add(homeRoot); err != nil && !errors.Is(err, os.ErrNotExist) {
		// best-effort
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename|fsnotify.Chmod) == 0 {
				continue
			}

			// Dynamic discovery: a new directory under /home likely means
			// useradd ran. Scan it for an authorized_keys and start
			// watching if found.
			if isHomeChild(ev.Name, homeRoot) && ev.Op&fsnotify.Create != 0 {
				addUserKeys(w, index, homeRoot)
			}

			meta := matchWatch(index, ev.Name)
			if meta.path == "" {
				continue
			}
			emit := event.New(meta.typ, meta.severity, meta.title).
				WithSource(Name).
				WithMessage(meta.message).
				WithField("path", ev.Name).
				WithField("op", ev.Op.String())
			if user := userFromPath(ev.Name, homeRoot); user != "" {
				emit.WithField("user", user)
			}
			out <- emit
		case err := <-w.Errors:
			if err != nil && ctx.Err() == nil {
				continue
			}
		}
	}
}

// addUserKeys scans homeRoot for ~/<user>/.ssh/authorized_keys files and
// registers a watch per file (idempotent — fsnotify ignores duplicates).
func addUserKeys(w *fsnotify.Watcher, index map[string]watch, homeRoot string) {
	entries, err := os.ReadDir(homeRoot)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		keyPath := filepath.Join(homeRoot, entry.Name(), ".ssh", "authorized_keys")
		sshDir := filepath.Join(homeRoot, entry.Name(), ".ssh")
		if _, ok := index[keyPath]; ok {
			continue
		}
		index[keyPath] = watch{
			path:     keyPath,
			typ:      event.TypeSSHKeyAdded,
			severity: event.SevHigh,
			title:    "User authorized_keys modified",
			message:  "a new SSH key may grant attacker persistent access to a user account",
		}
		index[sshDir] = watch{
			path:     sshDir,
			typ:      event.TypeSSHKeyAdded,
			severity: event.SevMedium,
			title:    "User .ssh directory changed",
		}
		_ = w.Add(keyPath)
		_ = w.Add(sshDir)
	}
}

func isHomeChild(p, homeRoot string) bool {
	cleaned := filepath.Clean(p)
	parent := filepath.Dir(cleaned)
	return parent == filepath.Clean(homeRoot)
}

// userFromPath extracts "<user>" from /home/<user>/... or /root/... paths.
func userFromPath(p, homeRoot string) string {
	cleaned := filepath.Clean(p)
	rootHome := filepath.Clean(homeRoot)
	if strings.HasPrefix(cleaned, rootHome+string(filepath.Separator)) {
		rest := cleaned[len(rootHome)+1:]
		if i := strings.Index(rest, string(filepath.Separator)); i > 0 {
			return rest[:i]
		}
		return rest
	}
	if strings.HasPrefix(cleaned, "/root") {
		return "root"
	}
	return ""
}

func matchWatch(index map[string]watch, p string) watch {
	if w, ok := index[p]; ok {
		return w
	}
	for path, w := range index {
		if strings.HasPrefix(p, path+"/") {
			return w
		}
	}
	return watch{}
}
