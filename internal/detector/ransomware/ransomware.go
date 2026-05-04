// Package ransomware watches /home for destructive rename/delete bursts and
// ransom-note patterns. It deliberately ignores ordinary write/create bursts:
// builds, deployments, package managers, and editor caches can legitimately
// write hundreds of files in seconds.
package ransomware

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
	"github.com/fsnotify/fsnotify"
)

const Name = "ransomware"

type Detector struct {
	Root      string
	Threshold int
	Window    time.Duration
}

func (d *Detector) Name() string { return Name }

func (d *Detector) Run(ctx context.Context, out chan<- *event.Event) error {
	root := d.Root
	if root == "" {
		root = "/home"
	}
	if _, err := os.Stat(root); err != nil {
		<-ctx.Done()
		return nil
	}
	threshold := d.Threshold
	if threshold <= 0 {
		threshold = 100
	}
	window := d.Window
	if window <= 0 {
		window = time.Minute
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()
	_ = filepath.WalkDir(root, func(path string, de os.DirEntry, err error) error {
		if err == nil && de.IsDir() {
			_ = w.Add(path)
		}
		return nil
	})
	var events []time.Time
	var lastSent time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-w.Events:
			now := time.Now()
			if ev.Op&fsnotify.Create != 0 {
				if info, err := os.Stat(ev.Name); err == nil && info.IsDir() {
					_ = w.Add(ev.Name)
				}
			}
			if ransomName(ev.Name) || encryptedName(ev.Name) {
				out <- event.New(event.TypeRansomwareActivity, event.SevCritical, "Ransomware file pattern detected").
					WithSource(Name).
					WithField("path", ev.Name).
					WithField("op", ev.Op.String()).
					WithField("reason", "ransomware_filename")
				continue
			}
			if !isDestructiveMassOp(ev.Op) {
				continue
			}
			events = append(events, now)
			cutoff := now.Add(-window)
			filtered := events[:0]
			for _, ts := range events {
				if !ts.Before(cutoff) {
					filtered = append(filtered, ts)
				}
			}
			events = filtered
			if len(events) >= threshold && now.Sub(lastSent) > window {
				lastSent = now
				out <- event.New(event.TypeRansomwareActivity, event.SevCritical, "Mass file rename/delete activity under /home").
					WithSource(Name).
					WithField("count", len(events)).
					WithField("window", window.String()).
					WithField("reason", "mass_rename_delete")
			}
		case <-w.Errors:
		}
	}
}

func isDestructiveMassOp(op fsnotify.Op) bool {
	return op&(fsnotify.Rename|fsnotify.Remove) != 0
}

func encryptedName(path string) bool {
	low := strings.ToLower(path)
	for _, suffix := range []string{".enc", ".locked", ".crypto", ".ryk", ".crypted"} {
		if strings.HasSuffix(low, suffix) {
			return true
		}
	}
	return false
}

func ransomName(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return strings.HasPrefix(base, "readme") && strings.Contains(base, "decrypt") ||
		strings.Contains(base, "how_to_decrypt") ||
		strings.Contains(base, "restore_files") ||
		strings.Contains(base, "ransom")
}
