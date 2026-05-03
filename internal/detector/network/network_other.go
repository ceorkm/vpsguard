//go:build !linux

package network

import (
	"context"

	"github.com/ceorkm/vpsguard/internal/event"
)

func run(ctx context.Context, _ chan<- *event.Event, _ *Detector) error {
	<-ctx.Done()
	return nil
}
