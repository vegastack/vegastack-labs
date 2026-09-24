package schedule

import (
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

var ErrNotDue = errors.New("schedule is not due")
var ErrWindowMissed = errors.New("schedule window missed")

type Slot struct {
	ScheduledAt, WindowOpensAt, WindowClosesAt time.Time
}

func Due(policy generated.ScheduledJobPolicy, observedAt time.Time) (Slot, error) {
	anchor, err := time.Parse(time.RFC3339, policy.AnchorAt)
	if err != nil || policy.IntervalSeconds <= 0 || policy.WindowSeconds <= 0 {
		return Slot{}, errors.New("invalid schedule")
	}
	anchor = anchor.UTC().Truncate(time.Second)
	observedAt = observedAt.UTC().Truncate(time.Second)
	if observedAt.Before(anchor) {
		return Slot{}, ErrNotDue
	}
	interval := time.Duration(policy.IntervalSeconds) * time.Second
	scheduled := anchor.Add(observedAt.Sub(anchor) / interval * interval)
	closeAt := scheduled.Add(time.Duration(policy.WindowSeconds) * time.Second)
	if !observedAt.Before(closeAt) && policy.CatchUp == "none" {
		return Slot{ScheduledAt: scheduled, WindowOpensAt: scheduled, WindowClosesAt: closeAt}, ErrWindowMissed
	}
	return Slot{ScheduledAt: scheduled, WindowOpensAt: scheduled, WindowClosesAt: closeAt}, nil
}

func Backoff(policy generated.ScheduledJobPolicy, attempt int64) time.Duration {
	value := policy.InitialBackoffSeconds
	for index := int64(1); index < attempt && value < policy.MaximumBackoffSeconds; index++ {
		value *= 2
		if value > policy.MaximumBackoffSeconds {
			value = policy.MaximumBackoffSeconds
		}
	}
	return time.Duration(value) * time.Second
}
