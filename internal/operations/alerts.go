// Package operations evaluates bounded observations independently of notification delivery.
package operations

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
	"regexp"
	"time"
)

var ErrInvalid = errors.New("invalid operations observation")
var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type Observation struct {
	TargetDigest string                `json:"targetDigest"`
	Class        string                `json:"class"`
	State        readmodel.SourceState `json:"state"`
	Severity     string                `json:"severity"`
	ObservedAt   time.Time             `json:"observedAt"`
	SampleAt     time.Time             `json:"sampleAt"`
	Verified     bool                  `json:"verified"`
}
type Alert struct {
	Key          string                `json:"key"`
	TargetDigest string                `json:"targetDigest"`
	Class        string                `json:"class"`
	Severity     string                `json:"severity"`
	State        readmodel.SourceState `json:"observationState"`
	Status       string                `json:"status"`
	FirstFailure *time.Time            `json:"firstFailure"`
	LastFailure  *time.Time            `json:"lastFailure"`
	LastGood     *time.Time            `json:"lastGood"`
	ObservedAt   time.Time             `json:"observedAt"`
	Occurrences  int64                 `json:"occurrences"`
	Consecutive  int64                 `json:"consecutive"`
	Generation   int64                 `json:"generation"`
}

func Digest(v string) string {
	s := sha256.Sum256([]byte(v))
	return "sha256:" + hex.EncodeToString(s[:])
}
func Valid(o Observation) bool {
	return digestPattern.MatchString(o.TargetDigest) && o.Class == "source-health" && (o.Severity == "critical" || o.Severity == "warning") && readmodel.ValidSourceState(o.State) && !o.ObservedAt.IsZero() && o.ObservedAt.Location() == time.UTC && (o.State != readmodel.SourceHealthy || o.Verified && !o.SampleAt.IsZero() && o.SampleAt.Location() == time.UTC && !o.SampleAt.After(o.ObservedAt))
}

// Evaluate never treats silence, stale data or destination success as recovery.
func Evaluate(a Alert, o Observation) (Alert, string, error) {
	if !Valid(o) || (!a.ObservedAt.IsZero() && !o.ObservedAt.After(a.ObservedAt)) {
		return Alert{}, "", ErrInvalid
	}
	key := Digest(o.TargetDigest + "\x00" + o.Class)
	if a.Key != "" && (a.Key != key || a.Severity != o.Severity) {
		return Alert{}, "", ErrInvalid
	}
	if a.Key == "" {
		a = Alert{Key: key, TargetDigest: o.TargetDigest, Class: o.Class, Severity: o.Severity, Status: "clear"}
	}
	a.State = o.State
	a.ObservedAt = o.ObservedAt
	if o.State == readmodel.SourceFailed {
		a.Occurrences++
		a.Consecutive++
		v := o.ObservedAt
		a.LastFailure = &v
		if a.FirstFailure == nil || a.Status == "closed" || a.Status == "clear" || a.Status != "open" && a.Consecutive == 1 {
			a.FirstFailure = &v
		}
		if a.Status != "open" {
			if o.Severity == "critical" || a.Consecutive >= 2 {
				a.Status = "open"
				a.Generation++
				return a, "opened", nil
			}
			a.Status = "pending"
		}
	} else {
		a.Consecutive = 0
		if o.State == readmodel.SourceHealthy {
			v := o.SampleAt
			a.LastGood = &v
			if a.Status == "open" && (a.LastFailure == nil || o.SampleAt.After(*a.LastFailure)) {
				a.Status = "closed"
				return a, "closed", nil
			}
			if a.Status != "open" && a.Status != "closed" {
				a.Status = "clear"
			}
		}
	}
	return a, "", nil
}
