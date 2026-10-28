package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/operations"
	"time"
)

// RecordOperationsObservation accepts only server-collected bounded facts. It is
// not exposed as a caller-supplied health upload or a declaration mutation.
func (s *Store) RecordOperationsObservation(ctx context.Context, expected RevisionToken, o operations.Observation, actor audit.Attribution, destination audit.DestinationID) (operations.Alert, error) {
	if audit.ValidateOutboxRequirements(func() []audit.OutboxRequirement {
		if destination == "" {
			return nil
		}
		return []audit.OutboxRequirement{{Destination: destination, Enabled: true}}
	}()) != nil || !operations.Valid(o) || o.ObservedAt.After(s.config.Clock().UTC()) {
		return operations.Alert{}, newStoreError("INPUT_INVALID", "operations-observation", false, nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.readyForTransaction(ctx); e != nil {
		return operations.Alert{}, e
	}
	tx, e := s.conn.BeginTx(ctx, nil)
	if e != nil {
		return operations.Alert{}, s.transactionError(ctx, e)
	}
	defer tx.Rollback()
	current, _, e := readRevisionAndAuditSequence(ctx, tx)
	if e != nil {
		return operations.Alert{}, e
	}
	if current != expected {
		return operations.Alert{}, newStoreError("STATE_CONFLICT", "operations-revision", false, nil)
	}
	key := operations.Digest(o.TargetDigest + "\x00" + o.Class)
	var raw []byte
	var previous operations.Alert
	e = tx.QueryRowContext(ctx, `SELECT alert_json FROM operations_alerts WHERE recovery_epoch=? AND alert_key=?`, expected.RecoveryEpoch, key).Scan(&raw)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return previous, e
	}
	if e == nil {
		if json.Unmarshal(raw, &previous) != nil {
			return previous, newStoreError("INTEGRITY_FAILURE", "operations-alert", false, nil)
		}
		if o.ObservedAt.Equal(previous.ObservedAt) {
			if o.State != previous.State || o.Severity != previous.Severity {
				return previous, newStoreError("STATE_CONFLICT", "operations-observation", false, nil)
			}
			return previous, nil
		}
	}
	next, transition, e := operations.Evaluate(previous, o)
	if e != nil {
		return previous, newStoreError("STATE_CONFLICT", "operations-observation", false, nil)
	}
	raw, e = json.Marshal(next)
	if e != nil {
		return previous, e
	}
	kind := "operations.observed"
	destinations := []audit.OutboxRequirement{}
	if transition != "" {
		kind = "operations.alert." + transition
		if destination != "" {
			destinations = append(destinations, audit.OutboxRequirement{Destination: destination, Enabled: true})
		}
	}
	digest := operations.Digest(string(raw))
	keyDigest := operations.Digest(key + o.ObservedAt.Format(time.RFC3339Nano))
	req := intentRequest{Expected: &expected, Idempotency: audit.IntentKey{Scope: "operations-observation", KeyDigest: audit.Fingerprint(keyDigest), RequestDigest: audit.Fingerprint(digest)}, Event: audit.EventDraft{Type: audit.EventType(kind), CorrelationID: "operations-" + key[7:39], Attribution: actor, Target: audit.Target{Kind: "operations-target", ID: o.TargetDigest}, After: fingerprintPtr(digest)}, Destinations: destinations}
	result, e := s.appendAuditInTx(ctx, tx, req, false, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO operations_alerts(recovery_epoch,alert_key,observed_at,alert_json) VALUES(?,?,?,?) ON CONFLICT(recovery_epoch,alert_key) DO UPDATE SET observed_at=excluded.observed_at,alert_json=excluded.alert_json`, expected.RecoveryEpoch, key, formatAuditTime(o.ObservedAt), raw)
		return err
	})
	if e != nil {
		return previous, e
	}
	if transition != "" {
		if _, e = tx.ExecContext(ctx, `INSERT INTO operations_transitions(event_id,recovery_epoch,alert_key,generation,transition) VALUES(?,?,?,?,?)`, result.EventID, expected.RecoveryEpoch, key, next.Generation, transition); e != nil {
			return previous, e
		}
	}
	if e = s.checkIdentity(ctx); e != nil {
		return previous, e
	}
	if e = tx.Commit(); e != nil {
		s.enterSafeMode("operations-commit-failure")
		return previous, s.transactionError(ctx, e)
	}
	s.events.signal()
	return next, nil
}
func fingerprintPtr(s string) *audit.Fingerprint { v := audit.Fingerprint(s); return &v }
func (s *Store) OperationsAlerts(ctx context.Context, expected RevisionToken) ([]operations.Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.readyForRead(ctx); e != nil {
		return nil, e
	}
	if s.health.Revision != expected {
		return nil, newStoreError("STATE_CONFLICT", "operations-revision", false, nil)
	}
	rows, e := s.conn.QueryContext(ctx, `SELECT alert_json FROM operations_alerts WHERE recovery_epoch=? ORDER BY alert_key LIMIT 201`, expected.RecoveryEpoch)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	items := []operations.Alert{}
	for rows.Next() {
		var raw []byte
		var a operations.Alert
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		if json.Unmarshal(raw, &a) != nil || len(items) == 200 {
			return nil, newStoreError("INTEGRITY_FAILURE", "operations-alert", false, nil)
		}
		items = append(items, a)
	}
	return items, rows.Err()
}

// OperationsDelivery is a sanitized audit projection plus its durable retry state.
type OperationsDelivery struct {
	Record audit.OutboxRecord
	Event  audit.Event
}

func (s *Store) DueOperationsDeliveries(ctx context.Context, destination audit.DestinationID, epoch int64, now time.Time) ([]OperationsDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.readyForRead(ctx); e != nil {
		return nil, e
	}
	if epoch != s.health.Revision.RecoveryEpoch {
		return nil, newStoreError("RECOVERY_EPOCH_MISMATCH", "operations-delivery", false, nil)
	}
	rows, e := s.conn.QueryContext(ctx, `SELECT o.outbox_id FROM outbox o JOIN operations_transitions t ON t.event_id=o.event_id WHERE t.recovery_epoch=? AND o.destination_id=? AND o.status IN ('pending','retry_wait') AND (o.next_attempt_at IS NULL OR o.next_attempt_at<=?) AND NOT EXISTS (SELECT 1 FROM outbox earlier JOIN operations_transitions t2 ON t2.event_id=earlier.event_id WHERE t2.recovery_epoch=t.recovery_epoch AND t2.alert_key=t.alert_key AND earlier.destination_id=o.destination_id AND earlier.outbox_id<o.outbox_id AND earlier.status IN ('pending','retry_wait','paused','dead_letter')) ORDER BY o.outbox_id LIMIT 20`, epoch, destination, formatAuditTime(now))
	if e != nil {
		return nil, e
	}
	ids := []audit.OutboxID{}
	for rows.Next() {
		var id audit.OutboxID
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	result := []OperationsDelivery{}
	for _, id := range ids {
		r, e := scanOutboxRecord(s.conn.QueryRowContext(ctx, outboxRecordQuery, id))
		if e != nil {
			return nil, e
		}
		var raw []byte
		if e = s.conn.QueryRowContext(ctx, `SELECT canonical_payload FROM audit_events WHERE event_id=?`, r.EventID).Scan(&raw); e != nil {
			return nil, e
		}
		var event audit.Event
		if json.Unmarshal(raw, &event) != nil {
			return nil, newStoreError("INTEGRITY_FAILURE", "operations-event", false, nil)
		}
		canonical, digest, e := audit.CanonicalEvent(event)
		if e != nil || string(canonical) != string(raw) || digest != r.PayloadSHA256 {
			return nil, newStoreError("INTEGRITY_FAILURE", "operations-event", false, nil)
		}
		result = append(result, OperationsDelivery{r, event})
	}
	return result, nil
}

// PrepareOperationsDelivery reuses the existing outbox integrity/quarantine check
// immediately before external delivery. No unverified payload reaches a sender.
func (s *Store) PrepareOperationsDelivery(ctx context.Context, d OperationsDelivery, now time.Time) error {
	raw, e := s.payloadForAttempt(ctx, d.Record.OutboxID, now)
	if e != nil {
		return e
	}
	canonical, digest, e := audit.CanonicalEvent(d.Event)
	if e != nil || string(raw) != string(canonical) || digest != d.Record.PayloadSHA256 {
		return newStoreError("INTEGRITY_FAILURE", "operations-delivery", false, nil)
	}
	return nil
}

// OperationsOutbox exposes only the existing closed outbox projection, newest
// 200 records in the current epoch. It never returns event/payload bytes.
func (s *Store) OperationsOutbox(ctx context.Context, expected RevisionToken) ([]audit.OutboxRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.readyForRead(ctx); e != nil {
		return nil, e
	}
	if s.health.Revision != expected {
		return nil, newStoreError("STATE_CONFLICT", "operations-revision", false, nil)
	}
	rows, e := s.conn.QueryContext(ctx, `SELECT o.outbox_id FROM outbox o JOIN operations_transitions t ON t.event_id=o.event_id WHERE t.recovery_epoch=? ORDER BY o.outbox_id DESC LIMIT 200`, expected.RecoveryEpoch)
	if e != nil {
		return nil, e
	}
	ids := []audit.OutboxID{}
	for rows.Next() {
		var id audit.OutboxID
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	result := []audit.OutboxRecord{}
	for _, id := range ids {
		r, e := scanOutboxRecord(s.conn.QueryRowContext(ctx, outboxRecordQuery, id))
		if e != nil {
			return nil, e
		}
		result = append(result, r)
	}
	return result, nil
}
