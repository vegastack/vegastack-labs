package stateexport

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/inventory"
)

type DraftSnapshot struct {
	StateRevision int64
	RecoveryEpoch int64
	Draft         inventory.CanonicalDraftSnapshot
}

type SnapshotSource interface {
	SnapshotInventoryDraft(context.Context, inventory.DraftRef) (DraftSnapshot, error)
}

type AuditAppendRequest struct {
	ExpectedStateRevision int64
	ExpectedRecoveryEpoch int64
	Idempotency           audit.IntentKey
	Event                 audit.EventDraft
	Destinations          []audit.OutboxRequirement
}

type AuditAppendResult struct {
	EventID       audit.EventID
	StateRevision int64
	RecoveryEpoch int64
	Created       bool
}

type PendingExportRequest struct {
	EventID         audit.EventID
	CorrelationID   string
	Attribution     audit.Attribution
	ExportID        string
	Draft           inventory.DraftRef
	StateRevision   int64
	RecoveryEpoch   int64
	PreviousDigest  *audit.Fingerprint
	RequestedDigest audit.Fingerprint
}

type AuditRepository interface {
	AppendExportAudit(context.Context, AuditAppendRequest) (AuditAppendResult, error)
	PendingExportRequests(context.Context, int) ([]PendingExportRequest, error)
}
