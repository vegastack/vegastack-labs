package store

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/audit"
)

// OperationalAuditRequest appends an attributed operational event without
// changing declared business state. Expected still binds the append to the
// caller's observed recovery epoch and state revision.
type OperationalAuditRequest struct {
	Expected     RevisionToken
	Idempotency  audit.IntentKey
	Event        audit.EventDraft
	Destinations []audit.OutboxRequirement
}

type OperationalAuditResult struct {
	EventID       audit.EventID
	StateRevision int64
	RecoveryEpoch int64
	Created       bool
}

// OperationalAuditAppender is the narrow seam consumed by later execution
// work. It deliberately exposes no database or delivery implementation.
type OperationalAuditAppender interface {
	AppendOperationalAudit(context.Context, OperationalAuditRequest) (OperationalAuditResult, error)
}

func (store *Store) AppendOperationalAudit(ctx context.Context, request OperationalAuditRequest) (OperationalAuditResult, error) {
	expected := request.Expected
	result, err := store.executeAuditIntent(ctx, intentRequest{
		Expected:     &expected,
		Idempotency:  request.Idempotency,
		Event:        request.Event,
		Destinations: request.Destinations,
	}, false, nil)
	if err != nil {
		return OperationalAuditResult{}, err
	}
	return OperationalAuditResult{
		EventID:       result.EventID,
		StateRevision: result.Commit.StateRevision,
		RecoveryEpoch: result.Commit.RecoveryEpoch,
		Created:       result.Created,
	}, nil
}
