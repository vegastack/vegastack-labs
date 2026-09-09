package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/vegastack/vegastack-labs/internal/audit"
)

type auditIntentStage string

const (
	auditAfterBusiness auditIntentStage = "after-business"
	auditAfterRevision auditIntentStage = "after-revision"
	auditAfterSequence auditIntentStage = "after-sequence"
	auditAfterEvent    auditIntentStage = "after-event"
	auditAfterIntent   auditIntentStage = "after-intent"
	auditAfterOutbox   auditIntentStage = "after-outbox"
	auditBeforeCommit  auditIntentStage = "before-commit"
	auditAfterCommit   auditIntentStage = "after-commit"
)

type intentRequest struct {
	Expected     *RevisionToken
	Idempotency  audit.IntentKey
	Event        audit.EventDraft
	Destinations []audit.OutboxRequirement
}

type intentResult struct {
	Commit  Commit
	EventID audit.EventID
	Created bool
}

func (store *Store) writeIntent(ctx context.Context, request intentRequest, business func(context.Context, *sql.Tx) error) (intentResult, error) {
	if business == nil {
		return intentResult{}, newStoreError("INPUT_INVALID", "audit-intent", false, nil)
	}
	return store.executeAuditIntent(ctx, request, true, business)
}

func (store *Store) executeAuditIntent(ctx context.Context, request intentRequest, advanceState bool, business func(context.Context, *sql.Tx) error) (intentResult, error) {
	if store == nil || audit.ValidateIntentKey(request.Idempotency) != nil || audit.ValidateEventDraft(request.Event) != nil || audit.ValidateOutboxRequirements(request.Destinations) != nil {
		return intentResult{}, newStoreError("INPUT_INVALID", "audit-intent", false, nil)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyForTransaction(ctx); err != nil {
		return intentResult{}, err
	}
	transaction, err := store.conn.BeginTx(ctx, nil)
	if err != nil {
		return intentResult{}, store.transactionError(ctx, err)
	}
	defer func() { _ = transaction.Rollback() }()

	result, err := store.appendAuditInTx(ctx, transaction, request, advanceState, business)
	if err != nil {
		if ctx.Err() != nil {
			return intentResult{}, interruptedError("audit-intent", ctx.Err())
		}
		if Code(err) == "INTEGRITY_FAILURE" {
			store.enterSafeMode("audit-intent-failure")
		}
		return intentResult{}, err
	}
	if err := store.checkIdentity(ctx); err != nil {
		return intentResult{}, err
	}
	if err := store.runAuditFault(auditBeforeCommit); err != nil {
		return intentResult{}, err
	}
	if store.beforeCommit != nil {
		if err := store.beforeCommit(); err != nil {
			store.enterSafeMode("commit-failure")
			return intentResult{}, databaseError("INTEGRITY_FAILURE", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		store.enterSafeMode("commit-failure")
		return intentResult{}, store.transactionError(ctx, err)
	}
	if result.Created {
		store.events.signal()
	}
	if result.Commit.Changed {
		store.health.Revision = RevisionToken{StateRevision: result.Commit.StateRevision, RecoveryEpoch: result.Commit.RecoveryEpoch}
	}
	if err := store.runAuditFault(auditAfterCommit); err != nil {
		store.enterSafeMode("commit-uncertain")
		return intentResult{}, err
	}
	return result, nil
}

func (store *Store) appendAuditInTx(ctx context.Context, transaction *sql.Tx, request intentRequest, advanceState bool, business func(context.Context, *sql.Tx) error) (intentResult, error) {
	current, sequence, err := readRevisionAndAuditSequence(ctx, transaction)
	if err != nil {
		return intentResult{}, store.transactionError(ctx, err)
	}
	if request.Expected != nil {
		if request.Expected.RecoveryEpoch != current.RecoveryEpoch {
			return intentResult{}, newStoreError("RECOVERY_EPOCH_MISMATCH", "database-revision", false, nil)
		}
		if request.Expected.StateRevision != current.StateRevision {
			return intentResult{}, newStoreError("STATE_CONFLICT", "database-revision", false, nil)
		}
	}

	var requestDigest string
	var existingEventID audit.EventID
	var existingRevision, existingEpoch int64
	err = transaction.QueryRowContext(ctx, `SELECT request_digest,event_id,state_revision,recovery_epoch FROM intent_keys WHERE scope=? AND key_digest=?`, request.Idempotency.Scope, request.Idempotency.KeyDigest).Scan(&requestDigest, &existingEventID, &existingRevision, &existingEpoch)
	if err == nil {
		if requestDigest != string(request.Idempotency.RequestDigest) {
			return intentResult{}, newStoreError("STATE_CONFLICT", "audit-intent-key", false, nil)
		}
		return intentResult{Commit: Commit{Changed: false, StateRevision: existingRevision, RecoveryEpoch: existingEpoch}, EventID: existingEventID, Created: false}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return intentResult{}, store.transactionError(ctx, err)
	}

	if business != nil {
		if err := business(ctx, transaction); err != nil {
			if Code(err) != "" {
				return intentResult{}, err
			}
			return intentResult{}, classifySQLiteError(ctx, err)
		}
	}
	if err := store.runAuditFault(auditAfterBusiness); err != nil {
		return intentResult{}, err
	}
	if ctx.Err() != nil {
		return intentResult{}, interruptedError("audit-intent", ctx.Err())
	}

	stateRevision := current.StateRevision
	if advanceState {
		changed, err := transaction.ExecContext(ctx, `UPDATE system_meta SET state_revision=state_revision+1 WHERE id=1 AND state_revision=? AND recovery_epoch=?`, current.StateRevision, current.RecoveryEpoch)
		if err != nil {
			return intentResult{}, store.transactionError(ctx, err)
		}
		rows, err := changed.RowsAffected()
		if err != nil || rows != 1 {
			return intentResult{}, newStoreError("STATE_CONFLICT", "database-revision", false, err)
		}
		stateRevision++
	}
	if err := store.runAuditFault(auditAfterRevision); err != nil {
		return intentResult{}, err
	}

	advanced, err := transaction.ExecContext(ctx, `UPDATE system_meta SET audit_sequence=audit_sequence+1 WHERE id=1 AND audit_sequence=? AND state_revision=? AND recovery_epoch=?`, sequence, stateRevision, current.RecoveryEpoch)
	if err != nil {
		return intentResult{}, store.transactionError(ctx, err)
	}
	rows, err := advanced.RowsAffected()
	if err != nil || rows != 1 {
		return intentResult{}, databaseError("INTEGRITY_FAILURE", err)
	}
	eventID := audit.EventID(sequence + 1)
	if err := store.runAuditFault(auditAfterSequence); err != nil {
		return intentResult{}, err
	}
	if err := validateEventReferences(ctx, transaction, request.Event, eventID); err != nil {
		return intentResult{}, err
	}

	now := store.config.Clock().UTC()
	event, err := audit.EventFromDraft(request.Event, eventID, now, current.RecoveryEpoch, stateRevision)
	if err != nil {
		return intentResult{}, newStoreError("INPUT_INVALID", "audit-event", false, nil)
	}
	payload, payloadDigest, err := audit.CanonicalEvent(event)
	if err != nil {
		return intentResult{}, newStoreError("INTEGRITY_FAILURE", "audit-event", false, nil)
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO audit_events(event_id,occurred_at,recovery_epoch,state_revision,event_type,correlation_id,causation_event_id,correction_of_event_id,principal_id,principal_method,responsible_human_principal_id,agent_name,agent_session_id,agent_source,target_kind,target_id,before_fingerprint,after_fingerprint,canonical_payload,payload_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		event.EventID, event.OccurredAt, event.RecoveryEpoch, event.StateRevision, event.Type, event.CorrelationID, event.CausationID, event.CorrectionOf,
		event.PrincipalID, event.PrincipalMethod, event.HumanID, event.AgentName, event.AgentSessionID, event.AgentSource, event.Target.Kind, event.Target.ID, event.Before, event.After, payload, payloadDigest)
	if err != nil {
		return intentResult{}, store.transactionError(ctx, err)
	}
	if err := store.runAuditFault(auditAfterEvent); err != nil {
		return intentResult{}, err
	}

	_, err = transaction.ExecContext(ctx, `INSERT INTO intent_keys(scope,key_digest,request_digest,event_id,state_revision,recovery_epoch,created_at) VALUES(?,?,?,?,?,?,?)`, request.Idempotency.Scope, request.Idempotency.KeyDigest, request.Idempotency.RequestDigest, eventID, stateRevision, current.RecoveryEpoch, event.OccurredAt)
	if err != nil {
		return intentResult{}, store.transactionError(ctx, err)
	}
	if err := store.runAuditFault(auditAfterIntent); err != nil {
		return intentResult{}, err
	}

	for _, requirement := range request.Destinations {
		status := audit.OutboxPaused
		if requirement.Enabled {
			status = audit.OutboxPending
		}
		dedupe := outboxDedupe(eventID, requirement.Destination, payloadDigest)
		_, err := transaction.ExecContext(ctx, `INSERT INTO outbox(event_id,destination_id,payload_schema,payload_version,payload_bytes,payload_sha256,dedupe_sha256,status,attempt_count,max_attempts,next_attempt_at,last_error_code,created_at,updated_at,delivered_at) VALUES(?,?,?,?,?,?,?,?,0,8,NULL,NULL,?,?,NULL)`, eventID, requirement.Destination, audit.EventSchema, audit.EventSchemaVersion, payload, payloadDigest, dedupe, status, event.OccurredAt, event.OccurredAt)
		if err != nil {
			return intentResult{}, store.transactionError(ctx, err)
		}
		if err := store.runAuditFault(auditAfterOutbox); err != nil {
			return intentResult{}, err
		}
	}
	return intentResult{Commit: Commit{Changed: advanceState, StateRevision: stateRevision, RecoveryEpoch: current.RecoveryEpoch}, EventID: eventID, Created: true}, nil
}

func readRevisionAndAuditSequence(ctx context.Context, transaction *sql.Tx) (RevisionToken, int64, error) {
	var token RevisionToken
	var sequence int64
	err := transaction.QueryRowContext(ctx, `SELECT state_revision,recovery_epoch,audit_sequence FROM system_meta WHERE id=1`).Scan(&token.StateRevision, &token.RecoveryEpoch, &sequence)
	if sequence < 0 {
		return RevisionToken{}, 0, errors.New("negative audit sequence")
	}
	return token, sequence, err
}

func validateEventReferences(ctx context.Context, transaction *sql.Tx, draft audit.EventDraft, next audit.EventID) error {
	for _, reference := range []*audit.EventID{draft.CausationID, draft.CorrectionOf} {
		if reference == nil {
			continue
		}
		var targetKind, targetID string
		if *reference >= next || transaction.QueryRowContext(ctx, `SELECT target_kind,target_id FROM audit_events WHERE event_id=?`, *reference).Scan(&targetKind, &targetID) != nil {
			return newStoreError("STATE_CONFLICT", "audit-event-reference", false, nil)
		}
		if reference == draft.CorrectionOf && (targetKind != string(draft.Target.Kind) || targetID != draft.Target.ID) {
			return newStoreError("STATE_CONFLICT", "audit-correction-target", false, nil)
		}
	}
	return nil
}

func outboxDedupe(eventID audit.EventID, destination audit.DestinationID, payload audit.Fingerprint) audit.Fingerprint {
	hash := sha256.New()
	var id [8]byte
	binary.BigEndian.PutUint64(id[:], uint64(eventID))
	_, _ = hash.Write(id[:])
	for _, value := range []string{string(destination), audit.EventSchema, audit.EventSchemaVersion, string(payload)} {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(value))
	}
	return audit.Fingerprint("sha256:" + hex.EncodeToString(hash.Sum(nil)))
}

func (store *Store) runAuditFault(stage auditIntentStage) error {
	if store.auditFault == nil {
		return nil
	}
	if err := store.auditFault(stage); err != nil {
		return databaseError("INTEGRITY_FAILURE", err)
	}
	return nil
}
