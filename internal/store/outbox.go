package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
)

func (store *Store) InspectOutbox(ctx context.Context, id audit.OutboxID) (audit.OutboxRecord, error) {
	if id <= 0 {
		return audit.OutboxRecord{}, newStoreError("INPUT_INVALID", "outbox-id", false, nil)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyForRead(ctx); err != nil {
		return audit.OutboxRecord{}, err
	}
	record, err := scanOutboxRecord(store.conn.QueryRowContext(ctx, outboxRecordQuery, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return audit.OutboxRecord{}, newStoreError("STATE_CONFLICT", "outbox-record", false, nil)
		}
		return audit.OutboxRecord{}, store.outboxReadError(ctx, err)
	}
	return record, nil
}

func (store *Store) RecordOutboxAttempt(ctx context.Context, attempt audit.OutboxAttempt) (audit.OutboxRecord, error) {
	if err := validateOutboxAttempt(attempt); err != nil {
		return audit.OutboxRecord{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyForTransaction(ctx); err != nil {
		return audit.OutboxRecord{}, err
	}
	transaction, err := store.conn.BeginTx(ctx, nil)
	if err != nil {
		return audit.OutboxRecord{}, store.transactionError(ctx, err)
	}
	defer func() { _ = transaction.Rollback() }()

	record, err := scanOutboxRecord(transaction.QueryRowContext(ctx, outboxRecordQuery, attempt.OutboxID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return audit.OutboxRecord{}, newStoreError("STATE_CONFLICT", "outbox-record", false, nil)
		}
		return audit.OutboxRecord{}, store.outboxReadError(ctx, err)
	}
	if record.AttemptCount != attempt.ExpectedAttempt || (record.Status != audit.OutboxPending && record.Status != audit.OutboxRetryWait) {
		return audit.OutboxRecord{}, newStoreError("STATE_CONFLICT", "outbox-attempt", false, nil)
	}
	if attempt.AttemptedAt.Before(record.UpdatedAt) || (record.NextAttemptAt != nil && attempt.AttemptedAt.Before(*record.NextAttemptAt)) {
		return audit.OutboxRecord{}, newStoreError("STATE_CONFLICT", "outbox-not-due", false, nil)
	}

	nextAttemptCount := record.AttemptCount + 1
	status := audit.OutboxDelivered
	var nextAttemptAt, lastErrorCode, deliveredAt any
	if attempt.Delivered {
		deliveredAt = formatAuditTime(attempt.AttemptedAt)
	} else {
		lastErrorCode = string(attempt.ErrorCode)
		if attempt.Retryable && nextAttemptCount < audit.MaxDeliveryAttempts {
			status = audit.OutboxRetryWait
			nextAttemptAt = formatAuditTime(attempt.AttemptedAt.Add(audit.RetryDelay(nextAttemptCount)))
		} else {
			status = audit.OutboxDeadLetter
		}
	}
	result, err := transaction.ExecContext(ctx, `UPDATE outbox SET status=?,attempt_count=?,next_attempt_at=?,last_error_code=?,updated_at=?,delivered_at=? WHERE outbox_id=? AND status=? AND attempt_count=?`,
		status, nextAttemptCount, nextAttemptAt, lastErrorCode, formatAuditTime(attempt.AttemptedAt), deliveredAt, attempt.OutboxID, record.Status, record.AttemptCount)
	if err != nil {
		return audit.OutboxRecord{}, store.transactionError(ctx, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return audit.OutboxRecord{}, store.transactionError(ctx, err)
	}
	if rows != 1 {
		return audit.OutboxRecord{}, newStoreError("STATE_CONFLICT", "outbox-attempt", false, nil)
	}
	updated, err := scanOutboxRecord(transaction.QueryRowContext(ctx, outboxRecordQuery, attempt.OutboxID))
	if err != nil {
		return audit.OutboxRecord{}, store.outboxReadError(ctx, err)
	}
	if err := store.checkIdentity(ctx); err != nil {
		return audit.OutboxRecord{}, err
	}
	if err := transaction.Commit(); err != nil {
		store.enterSafeMode("outbox-commit-failure")
		return audit.OutboxRecord{}, store.transactionError(ctx, err)
	}
	return updated, nil
}

// payloadForAttempt is intentionally package-private. A future destination
// adapter may receive verified bytes through a store-owned dispatcher, but no
// sender, claim loop, or network behavior exists in this issue.
func (store *Store) payloadForAttempt(ctx context.Context, id audit.OutboxID, now time.Time) ([]byte, error) {
	if id <= 0 || now.IsZero() || now.Location() != time.UTC {
		return nil, newStoreError("INPUT_INVALID", "outbox-attempt", false, nil)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyForTransaction(ctx); err != nil {
		return nil, err
	}
	transaction, err := store.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, store.transactionError(ctx, err)
	}
	defer func() { _ = transaction.Rollback() }()

	var schema, version, digest, eventDigest string
	var status audit.OutboxStatus
	var payload, eventPayload []byte
	var nextAttemptAt sql.NullString
	err = transaction.QueryRowContext(ctx, `SELECT o.payload_schema,o.payload_version,o.payload_bytes,o.payload_sha256,o.status,o.next_attempt_at,e.canonical_payload,e.payload_sha256 FROM outbox o JOIN audit_events e ON e.event_id=o.event_id WHERE o.outbox_id=?`, id).Scan(&schema, &version, &payload, &digest, &status, &nextAttemptAt, &eventPayload, &eventDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, newStoreError("STATE_CONFLICT", "outbox-record", false, nil)
	}
	if err != nil {
		return nil, store.transactionError(ctx, err)
	}
	if status != audit.OutboxPending && status != audit.OutboxRetryWait {
		return nil, newStoreError("STATE_CONFLICT", "outbox-attempt", false, nil)
	}
	if nextAttemptAt.Valid {
		due, parseErr := parseAuditTime(nextAttemptAt.String)
		if parseErr != nil {
			return nil, store.outboxReadError(ctx, parseErr)
		}
		if now.Before(due) {
			return nil, newStoreError("STATE_CONFLICT", "outbox-not-due", false, nil)
		}
	}
	digestBytes := sha256.Sum256(payload)
	actualDigest := "sha256:" + hex.EncodeToString(digestBytes[:])
	var event audit.Event
	canonical, canonicalDigest, canonicalErr := audit.CanonicalEvent(event)
	if jsonErr := json.Unmarshal(eventPayload, &event); jsonErr == nil {
		canonical, canonicalDigest, canonicalErr = audit.CanonicalEvent(event)
	}
	if schema != audit.EventSchema || version != audit.EventSchemaVersion || digest != actualDigest || digest != eventDigest || !bytes.Equal(payload, eventPayload) || canonicalErr != nil || !bytes.Equal(canonical, eventPayload) || string(canonicalDigest) != eventDigest {
		result, updateErr := transaction.ExecContext(ctx, `UPDATE outbox SET status='dead_letter',next_attempt_at=NULL,last_error_code=?,updated_at=?,delivered_at=NULL WHERE outbox_id=? AND status=?`, audit.PayloadInvalid, formatAuditTime(now), id, status)
		if updateErr != nil {
			return nil, store.transactionError(ctx, updateErr)
		}
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil || rows != 1 {
			if rowsErr == nil {
				rowsErr = errors.New("outbox quarantine lost compare-and-transition")
			}
			return nil, store.transactionError(ctx, rowsErr)
		}
		if commitErr := transaction.Commit(); commitErr != nil {
			store.enterSafeMode("outbox-commit-failure")
			return nil, store.transactionError(ctx, commitErr)
		}
		store.enterSafeMode("outbox-payload-integrity")
		return nil, newStoreError("INTEGRITY_FAILURE", "outbox-payload", false, nil)
	}
	return append([]byte(nil), payload...), nil
}

func validateOutboxAttempt(attempt audit.OutboxAttempt) error {
	if attempt.OutboxID <= 0 || attempt.ExpectedAttempt < 0 || attempt.ExpectedAttempt >= audit.MaxDeliveryAttempts || attempt.AttemptedAt.IsZero() || attempt.AttemptedAt.Location() != time.UTC {
		return newStoreError("INPUT_INVALID", "outbox-attempt", false, nil)
	}
	if attempt.Delivered {
		if attempt.Retryable || attempt.ErrorCode != "" {
			return newStoreError("INPUT_INVALID", "outbox-attempt", false, nil)
		}
		return nil
	}
	if !audit.ValidDeliveryErrorCode(attempt.ErrorCode) {
		return newStoreError("INPUT_INVALID", "outbox-attempt", false, nil)
	}
	return nil
}

const outboxRecordQuery = `SELECT outbox_id,event_id,destination_id,payload_schema,payload_version,payload_sha256,dedupe_sha256,status,attempt_count,max_attempts,next_attempt_at,last_error_code,created_at,updated_at,delivered_at FROM outbox WHERE outbox_id=?`

type rowScanner interface {
	Scan(...any) error
}

func scanOutboxRecord(row rowScanner) (audit.OutboxRecord, error) {
	var record audit.OutboxRecord
	var nextAttemptAt, lastErrorCode, deliveredAt sql.NullString
	var createdAt, updatedAt string
	err := row.Scan(&record.OutboxID, &record.EventID, &record.Destination, &record.PayloadSchema, &record.PayloadVersion, &record.PayloadSHA256, &record.DedupeSHA256, &record.Status, &record.AttemptCount, &record.MaxAttempts, &nextAttemptAt, &lastErrorCode, &createdAt, &updatedAt, &deliveredAt)
	if err != nil {
		return audit.OutboxRecord{}, err
	}
	if record.OutboxID <= 0 || record.EventID <= 0 || record.PayloadSchema != audit.EventSchema || record.PayloadVersion != audit.EventSchemaVersion ||
		audit.ValidateOutboxRequirements([]audit.OutboxRequirement{{Destination: record.Destination, Enabled: true}}) != nil ||
		record.MaxAttempts != audit.MaxDeliveryAttempts || record.AttemptCount < 0 || record.AttemptCount > record.MaxAttempts || !audit.ValidFingerprint(record.PayloadSHA256) || !audit.ValidFingerprint(record.DedupeSHA256) {
		return audit.OutboxRecord{}, errors.New("invalid persisted outbox record")
	}
	if record.CreatedAt, err = parseAuditTime(createdAt); err != nil {
		return audit.OutboxRecord{}, err
	}
	if record.UpdatedAt, err = parseAuditTime(updatedAt); err != nil {
		return audit.OutboxRecord{}, err
	}
	if nextAttemptAt.Valid {
		value, parseErr := parseAuditTime(nextAttemptAt.String)
		if parseErr != nil {
			return audit.OutboxRecord{}, parseErr
		}
		record.NextAttemptAt = &value
	}
	if lastErrorCode.Valid {
		value := audit.DeliveryErrorCode(lastErrorCode.String)
		if !audit.ValidDeliveryErrorCode(value) {
			return audit.OutboxRecord{}, errors.New("invalid persisted outbox error code")
		}
		record.LastErrorCode = &value
	}
	if deliveredAt.Valid {
		value, parseErr := parseAuditTime(deliveredAt.String)
		if parseErr != nil {
			return audit.OutboxRecord{}, parseErr
		}
		record.DeliveredAt = &value
	}
	if record.UpdatedAt.Before(record.CreatedAt) || !validOutboxState(record) {
		return audit.OutboxRecord{}, errors.New("invalid persisted outbox state")
	}
	return record, nil
}

func validOutboxState(record audit.OutboxRecord) bool {
	switch record.Status {
	case audit.OutboxPending, audit.OutboxPaused:
		return record.AttemptCount == 0 && record.NextAttemptAt == nil && record.LastErrorCode == nil && record.DeliveredAt == nil
	case audit.OutboxRetryWait:
		return record.AttemptCount > 0 && record.AttemptCount < record.MaxAttempts && record.NextAttemptAt != nil && record.LastErrorCode != nil && record.DeliveredAt == nil
	case audit.OutboxDelivered:
		return record.AttemptCount > 0 && record.NextAttemptAt == nil && record.LastErrorCode == nil && record.DeliveredAt != nil
	case audit.OutboxDeadLetter:
		return record.NextAttemptAt == nil && record.LastErrorCode != nil && record.DeliveredAt == nil
	default:
		return false
	}
}

func (store *Store) outboxReadError(ctx context.Context, cause error) error {
	if ctx.Err() != nil {
		return interruptedError("outbox", ctx.Err())
	}
	store.enterSafeMode("outbox-record-integrity")
	return databaseError("INTEGRITY_FAILURE", cause)
}

func formatAuditTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func parseAuditTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("invalid persisted audit timestamp")
	}
	return parsed.UTC(), nil
}
