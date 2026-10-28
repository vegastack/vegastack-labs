package operations

import (
	"github.com/vegastack/vegastack-labs/internal/readmodel"
	"testing"
	"time"
)

func TestFailureDedupeAndVerifiedRecovery(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	o := Observation{TargetDigest: Digest("target"), Class: "source-health", State: readmodel.SourceFailed, ObservedAt: now, Severity: "critical"}
	a, transition, e := Evaluate(Alert{}, o)
	if e != nil || transition != "opened" || a.Occurrences != 1 {
		t.Fatalf("open %#v %s %v", a, transition, e)
	}
	o.ObservedAt = now.Add(time.Second)
	a, transition, e = Evaluate(a, o)
	if e != nil || transition != "" || a.Occurrences != 2 {
		t.Fatalf("duplicate %#v %s %v", a, transition, e)
	}
	for _, s := range []readmodel.SourceState{readmodel.SourceUnknown, readmodel.SourceStale, readmodel.SourceUnavailable} {
		o.State = s
		o.ObservedAt = o.ObservedAt.Add(time.Second)
		a, transition, e = Evaluate(a, o)
		if e != nil || transition != "" || a.Status != "open" {
			t.Fatal("absence closed failure", a, transition, e)
		}
	}
	o.State = readmodel.SourceHealthy
	o.ObservedAt = o.ObservedAt.Add(time.Second)
	if _, _, e = Evaluate(a, o); e == nil {
		t.Fatal("unverified recovery accepted")
	}
	o.Verified = true
	o.SampleAt = now
	old, tr, err := Evaluate(a, o)
	if err != nil || tr != "" || old.Status != "open" {
		t.Fatal("older healthy sample closed a newer failure", old, tr, err)
	}
	o.SampleAt = o.ObservedAt
	a, transition, e = Evaluate(a, o)
	if e != nil || transition != "closed" || a.Status != "closed" {
		t.Fatal(a, transition, e)
	}
	if _, _, e = Evaluate(a, o); e == nil {
		t.Fatal("replayed observation accepted")
	}
}
func TestWarningNeedsTwoConsecutiveFailures(t *testing.T) {
	now := time.Now().UTC()
	o := Observation{TargetDigest: Digest("target"), Class: "source-health", State: readmodel.SourceFailed, ObservedAt: now, Severity: "warning"}
	a, tr, e := Evaluate(Alert{}, o)
	if e != nil || tr != "" || a.Status != "pending" {
		t.Fatal(a, tr, e)
	}
	o.State = readmodel.SourceUnknown
	o.ObservedAt = now.Add(time.Second)
	a, _, _ = Evaluate(a, o)
	o.State = readmodel.SourceFailed
	o.ObservedAt = now.Add(2 * time.Second)
	a, tr, e = Evaluate(a, o)
	if e != nil || tr != "" {
		t.Fatal("non-consecutive warning opened", a, tr, e)
	}
	o.ObservedAt = now.Add(3 * time.Second)
	_, tr, e = Evaluate(a, o)
	if e != nil || tr != "opened" {
		t.Fatal(tr, e)
	}
}
