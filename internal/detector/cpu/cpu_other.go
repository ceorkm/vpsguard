//go:build !linux

package cpu

import (
	"context"

	"github.com/ceorkm/vpsguard/internal/event"
)

func run(ctx context.Context, _ chan<- *event.Event, _ float64, _ int) error {
	<-ctx.Done()
	return nil
}
