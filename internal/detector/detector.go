package detector

import (
	"context"

	"github.com/ceorkm/vpsguard/internal/event"
)

// Detector is anything that emits events. Each detector runs as its own goroutine.
type Detector interface {
	Name() string
	Run(ctx context.Context, out chan<- *event.Event) error
}
