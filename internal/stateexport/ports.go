package stateexport

import (
	"context"
	"fmt"
	"regexp"
	"strconv"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/inventory"
)

const exportTargetPrefix = "inventory-draft-export-r"

var exportTargetPattern = regexp.MustCompile(`^inventory-draft-export-r([1-9][0-9]*)$`)

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

func ExportTarget(ref inventory.DraftRef) (audit.Target, error) {
	if ref.ID == "" || len(ref.ID) > inventory.MaxTokenBytes || ref.Revision < 1 {
		return audit.Target{}, exportError("INPUT_INVALID", "inventory-export-draft")
	}
	target := audit.Target{Kind: audit.TargetKind(fmt.Sprintf("%s%d", exportTargetPrefix, ref.Revision)), ID: string(ref.ID)}
	if len(target.Kind) > 64 {
		return audit.Target{}, exportError("INPUT_INVALID", "inventory-export-draft")
	}
	return target, nil
}

func ExportTargetRevision(kind audit.TargetKind) (int64, bool) {
	match := exportTargetPattern.FindStringSubmatch(string(kind))
	if len(match) != 2 {
		return 0, false
	}
	revision, err := strconv.ParseInt(match[1], 10, 64)
	return revision, err == nil && revision > 0
}
