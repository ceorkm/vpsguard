//go:build linux

package cpu

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
)

const (
	sampleInterval = 5 * time.Second
)

type sample struct {
	idle  uint64
	total uint64
}

func run(ctx context.Context, out chan<- *event.Event, threshold float64, sustainSec int) error {
	prev, err := readStat()
	if err != nil {
		return fmt.Errorf("cpu: %w", err)
	}

	t := time.NewTicker(sampleInterval)
	defer t.Stop()

	var aboveSince *time.Time
	var alerted bool

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			cur, err := readStat()
			if err != nil {
				continue
			}
			usage := pctBusy(prev, cur)
			prev = cur

			if usage >= threshold {
				if aboveSince == nil {
					now := time.Now()
					aboveSince = &now
					alerted = false
				} else if !alerted && time.Since(*aboveSince) >= time.Duration(sustainSec)*time.Second {
					out <- event.New(event.TypeCPUSpike, event.SevHigh,
						"Sustained high CPU usage").
						WithSource(Name).
						WithMessage(fmt.Sprintf("CPU has been at or above %.0f%% for %d seconds", threshold, sustainSec)).
						WithField("usage_pct", usage).
						WithField("threshold_pct", threshold).
						WithField("sustained_seconds", int(time.Since(*aboveSince).Seconds()))
					alerted = true
				}
			} else {
				aboveSince = nil
				alerted = false
			}
		}
	}
}

// pctBusy returns 0–100. Standard /proc/stat math: 100 * (1 - delta_idle/delta_total).
func pctBusy(prev, cur sample) float64 {
	dt := cur.total - prev.total
	di := cur.idle - prev.idle
	if dt == 0 {
		return 0
	}
	busy := float64(dt-di) / float64(dt) * 100
	if busy < 0 {
		busy = 0
	}
	if busy > 100 {
		busy = 100
	}
	return busy
}

func readStat() (sample, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return sample{}, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:]
		var nums []uint64
		for _, fld := range fields {
			n, err := strconv.ParseUint(fld, 10, 64)
			if err != nil {
				return sample{}, err
			}
			nums = append(nums, n)
		}
		// indices: user nice system idle iowait irq softirq steal guest guest_nice
		if len(nums) < 4 {
			return sample{}, fmt.Errorf("cpu: malformed /proc/stat")
		}
		idle := nums[3]
		if len(nums) > 4 {
			idle += nums[4] // iowait counts as idle
		}
		var total uint64
		for _, n := range nums {
			total += n
		}
		return sample{idle: idle, total: total}, nil
	}
	return sample{}, fmt.Errorf("cpu: no 'cpu' line in /proc/stat")
}
