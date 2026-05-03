// Package selfhash detects replacement of the running vpsguard binary.
package selfhash

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
)

const Name = "selfhash"

type Detector struct {
	Path     string
	Interval time.Duration
}

func (d *Detector) Name() string { return Name }

func (d *Detector) Run(ctx context.Context, out chan<- *event.Event) error {
	path := d.Path
	if path == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("selfhash: executable path: %w", err)
		}
		path = exe
	}
	baseline, err := hashFile(path)
	if err != nil {
		return fmt.Errorf("selfhash: baseline %s: %w", path, err)
	}
	interval := d.Interval
	if interval <= 0 {
		interval = 60 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	alerted := false
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			current, err := hashFile(path)
			if err != nil {
				continue
			}
			if current == baseline {
				alerted = false
				continue
			}
			if alerted {
				continue
			}
			alerted = true
			out <- event.New(event.TypeAgentBinaryModified, event.SevCritical,
				"vpsguard binary changed on disk").
				WithSource(Name).
				WithMessage("the running agent binary no longer matches its startup hash — possible tampering or upgrade").
				WithField("path", path).
				WithField("startup_sha256", baseline).
				WithField("current_sha256", current)
		}
	}
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
