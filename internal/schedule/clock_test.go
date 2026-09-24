package schedule

import (
	"testing"
	"time"
)

func TestDueUsesAnchoredUTCSlotsAcrossClockJumps(t *testing.T) {
	policy := validPolicy()
	first, err := Due(policy, time.Date(2026, 9, 16, 1, 10, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := Due(policy, time.Date(2026, 9, 16, 1, 14, 59, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !first.ScheduledAt.Equal(duplicate.ScheduledAt) || first.ScheduledAt.Format(time.RFC3339) != "2026-09-16T01:00:00Z" {
		t.Fatalf("slots differ: %#v %#v", first, duplicate)
	}
	backward, err := Due(policy, time.Date(2026, 9, 16, 0, 10, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !backward.ScheduledAt.Before(first.ScheduledAt) {
		t.Fatal("backward clock was not mapped to its durable prior slot")
	}
	if got := Backoff(policy, 5); got != time.Minute {
		t.Fatalf("backoff=%s", got)
	}
}
