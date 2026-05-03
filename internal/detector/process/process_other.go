//go:build !linux

package process

import (
	"context"

	"github.com/ceorkm/vpsguard/internal/event"
)

// Stub for non-Linux platforms (development on macOS).
// vpsguard's production target is Linux; this keeps the project buildable.
func run(ctx context.Context, _ chan<- *event.Event, _ *Detector) error {
	<-ctx.Done()
	return nil
}
