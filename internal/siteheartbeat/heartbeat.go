// Package siteheartbeat defines the closed, sanitized site-silence signal.
// It grants no qualification, approval or control authority.
package siteheartbeat

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

const Schema = "vegastack-labs.dev/site-heartbeat"
const SchemaVersion = "1.0.0"
const MaximumBytes = 1024

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type Snapshot struct {
	SiteDigest                   string
	ObservedAt                   time.Time
	StateRevision, RecoveryEpoch int64
}
type Heartbeat struct {
	Schema        string `json:"schema"`
	SchemaVersion string `json:"schemaVersion"`
	SiteDigest    string `json:"siteDigest"`
	ObservedAt    string `json:"observedAt"`
	StateRevision int64  `json:"stateRevision"`
	RecoveryEpoch int64  `json:"recoveryEpoch"`
}

func Encode(snapshot Snapshot, now time.Time) ([]byte, error) {
	if !digestPattern.MatchString(snapshot.SiteDigest) || snapshot.ObservedAt.IsZero() || now.IsZero() || snapshot.ObservedAt.After(now) || now.Sub(snapshot.ObservedAt) > time.Minute || snapshot.StateRevision < 0 || snapshot.RecoveryEpoch < 0 || snapshot.StateRevision > 9007199254740991 || snapshot.RecoveryEpoch > 9007199254740991 {
		return nil, errors.New("site heartbeat input unavailable")
	}
	return json.Marshal(Heartbeat{Schema: Schema, SchemaVersion: SchemaVersion, SiteDigest: snapshot.SiteDigest, ObservedAt: snapshot.ObservedAt.UTC().Format(time.RFC3339), StateRevision: snapshot.StateRevision, RecoveryEpoch: snapshot.RecoveryEpoch})
}

type Source interface {
	HeartbeatSnapshot(context.Context) (Snapshot, error)
}
type Writer interface {
	WriteHeartbeat(context.Context, []byte) error
}
type Publisher struct {
	Source Source
	Writer Writer
	Clock  func() time.Time
}

func (p Publisher) Publish(ctx context.Context) error {
	if p.Source == nil || p.Writer == nil || p.Clock == nil {
		return errors.New("site heartbeat publisher unavailable")
	}
	snapshot, err := p.Source.HeartbeatSnapshot(ctx)
	if err != nil {
		return errors.New("site heartbeat authority unavailable")
	}
	payload, err := Encode(snapshot, p.Clock().UTC())
	if err != nil {
		return err
	}
	if err = p.Writer.WriteHeartbeat(ctx, payload); err != nil {
		return errors.New("site heartbeat delivery unavailable")
	}
	return nil
}
