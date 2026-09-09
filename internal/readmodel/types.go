// Package readmodel defines safe, provider-neutral API read projections.
package readmodel

import (
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/inventory"
)

type RevisionToken struct {
	StateRevision int64
	RecoveryEpoch int64
}

type DatabaseStatus struct {
	Mode                 string
	SchemaVersion        uint64
	SQLiteVersion        string
	Revision             RevisionToken
	MutationEnabled      bool
	RecoveryPending      bool
	IntegrityStatus      string
	LastIntegrityCheckAt *time.Time
	SafeModeReason       string
}

type Summary struct {
	DatabaseMode      string
	ReadAvailable     bool
	MutationAvailable bool
	DraftCount        int64
	ValidDraftCount   int64
	BlockedDraftCount int64
	LastEventID       int64
	RecoveryEpoch     int64
	StateRevision     int64
}

type Draft struct {
	Summary inventory.DraftSummary
	Source  inventory.SourceDescriptor
}
type DraftPage struct {
	Items    []inventory.DraftSummary
	HasMore  bool
	Last     *inventory.DraftListQuery
	Snapshot RevisionToken
}

type Record struct {
	Kind            string
	LocalID         inventory.LocalID
	AssetKind       inventory.AssetKind
	Lifecycle       inventory.AssetLifecycle
	AssetID         inventory.LocalID
	ParentID        inventory.LocalID
	TargetID        inventory.LocalID
	Value           string
	SubjectID       inventory.LocalID
	ObservationKind string
	State           string
	ObservedAt      *time.Time
	Source          string
}

type RecordPage struct {
	Items    []Record
	HasMore  bool
	Last     *inventory.RecordListQuery
	Snapshot RevisionToken
}
type EventBatch struct {
	Items     []audit.Event
	HighWater audit.EventID
}
