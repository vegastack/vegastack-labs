//go:build linux

package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
)

func TestOutboxRetryScheduleCapsAndPoisonPayloadNeverEscapes(t *testing.T) {
	store, id := storePendingOutbox(t)
	now := outboxAttemptTime(t, store, id)
	if payload, err := store.payloadForAttempt(context.Background(), id, now); err != nil || len(payload) == 0 {
		t.Fatalf("verified payload = %d bytes, %v", len(payload), err)
	}
	attemptedAt := now
	for attempt := 1; attempt <= audit.MaxDeliveryAttempts; attempt++ {
		got, err := store.RecordOutboxAttempt(context.Background(), audit.OutboxAttempt{OutboxID: id, ExpectedAttempt: attempt - 1, Retryable: true, ErrorCode: audit.DestinationUnavailable, AttemptedAt: attemptedAt})
		if err != nil {
			t.Fatal(err)
		}
		if attempt < audit.MaxDeliveryAttempts && (got.NextAttemptAt == nil || got.NextAttemptAt.Sub(attemptedAt) != audit.RetryDelay(attempt)) {
			t.Fatalf("next attempt %d = %v", attempt, got.NextAttemptAt)
		}
		if attempt == 1 {
			if payload, err := store.payloadForAttempt(context.Background(), id, now); len(payload) != 0 || Code(err) != "STATE_CONFLICT" {
				t.Fatalf("early payload = %d bytes, %v", len(payload), err)
			}
			if payload, err := store.payloadForAttempt(context.Background(), id, now.Add(audit.RetryDelay(attempt))); len(payload) == 0 || err != nil {
				t.Fatalf("due payload = %d bytes, %v", len(payload), err)
			}
		}
		if got.NextAttemptAt != nil {
			attemptedAt = *got.NextAttemptAt
		}
	}
	if got, _ := store.InspectOutbox(context.Background(), id); got.Status != audit.OutboxDeadLetter || got.AttemptCount != 8 {
		t.Fatalf("final = %#v", got)
	}

	poisonStore, poisonID := storePendingOutbox(t)
	poisonNow := outboxAttemptTime(t, poisonStore, poisonID)
	if _, err := poisonStore.conn.ExecContext(context.Background(), `DROP TRIGGER outbox_immutable_payload`); err != nil {
		t.Fatal(err)
	}
	if _, err := poisonStore.conn.ExecContext(context.Background(), `UPDATE outbox SET payload_sha256='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE outbox_id=?`, poisonID); err != nil {
		t.Fatal(err)
	}
	payload, err := poisonStore.payloadForAttempt(context.Background(), poisonID, poisonNow)
	if len(payload) != 0 || Code(err) != "INTEGRITY_FAILURE" {
		t.Fatalf("poison result = %q, %v", payload, err)
	}
	if got, _ := poisonStore.InspectOutbox(context.Background(), poisonID); got.Status != audit.OutboxDeadLetter || got.LastErrorCode == nil || *got.LastErrorCode != audit.PayloadInvalid {
		t.Fatalf("poison state = %#v", got)
	}
}

func TestOutboxTransitionsRejectStalePausedTerminalAndUnsafeErrors(t *testing.T) {
	t.Run("delivered", func(t *testing.T) {
		store, id := storePendingOutbox(t)
		now := outboxAttemptTime(t, store, id)
		got, err := store.RecordOutboxAttempt(context.Background(), audit.OutboxAttempt{OutboxID: id, ExpectedAttempt: 0, Delivered: true, AttemptedAt: now})
		if err != nil || got.Status != audit.OutboxDelivered || got.DeliveredAt == nil || got.AttemptCount != 1 {
			t.Fatalf("delivered = %#v, %v", got, err)
		}
		if _, err := store.RecordOutboxAttempt(context.Background(), audit.OutboxAttempt{OutboxID: id, ExpectedAttempt: 0, Delivered: true, AttemptedAt: now}); Code(err) != "STATE_CONFLICT" {
			t.Fatalf("terminal retry code = %q", Code(err))
		}
		if got := readRevisionAndSequence(t, store); got != (revisionAndSequence{AuditSequence: 1}) {
			t.Fatalf("audit metadata changed = %#v", got)
		}
	})
	t.Run("paused and unsafe", func(t *testing.T) {
		store := openAuditTestStore(t)
		request := operationalAuditRequest("d", []audit.OutboxRequirement{{Destination: "audit-paused", Enabled: false}})
		if _, err := store.AppendOperationalAudit(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		var id audit.OutboxID
		if err := store.conn.QueryRowContext(context.Background(), `SELECT outbox_id FROM outbox`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		now := store.config.Clock().UTC().Add(time.Second)
		if _, err := store.RecordOutboxAttempt(context.Background(), audit.OutboxAttempt{OutboxID: id, ExpectedAttempt: 0, Retryable: true, ErrorCode: audit.DeliveryErrorCode("raw hostile error"), AttemptedAt: now}); Code(err) != "INPUT_INVALID" {
			t.Fatalf("unsafe error code = %q", Code(err))
		}
		if _, err := store.RecordOutboxAttempt(context.Background(), audit.OutboxAttempt{OutboxID: id, ExpectedAttempt: 0, Retryable: true, ErrorCode: audit.DestinationUnavailable, AttemptedAt: now}); Code(err) != "STATE_CONFLICT" {
			t.Fatalf("paused attempt code = %q", Code(err))
		}
	})
	t.Run("non-retryable", func(t *testing.T) {
		store, id := storePendingOutbox(t)
		now := outboxAttemptTime(t, store, id)
		got, err := store.RecordOutboxAttempt(context.Background(), audit.OutboxAttempt{OutboxID: id, ExpectedAttempt: 0, ErrorCode: audit.DeliveryRejected, AttemptedAt: now})
		if err != nil || got.Status != audit.OutboxDeadLetter || got.AttemptCount != 1 || got.LastErrorCode == nil || *got.LastErrorCode != audit.DeliveryRejected {
			t.Fatalf("non-retryable = %#v, %v", got, err)
		}
	})
}

func TestOutboxAttemptCompareAndTransitionAllowsOneConcurrentWinner(t *testing.T) {
	store, id := storePendingOutbox(t)
	now := outboxAttemptTime(t, store, id)
	start := make(chan struct{})
	errors := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := store.RecordOutboxAttempt(context.Background(), audit.OutboxAttempt{OutboxID: id, ExpectedAttempt: 0, Delivered: true, AttemptedAt: now})
			errors <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errors)
	var succeeded, conflicted int
	for err := range errors {
		if err == nil {
			succeeded++
		} else if Code(err) == "STATE_CONFLICT" {
			conflicted++
		} else {
			t.Fatalf("attempt error = %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("succeeded/conflicted = %d/%d", succeeded, conflicted)
	}
}

func storePendingOutbox(t *testing.T) (*Store, audit.OutboxID) {
	t.Helper()
	store := openAuditTestStore(t)
	request := operationalAuditRequest("e", []audit.OutboxRequirement{{Destination: "audit-primary", Enabled: true}})
	if _, err := store.AppendOperationalAudit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	var id audit.OutboxID
	if err := store.conn.QueryRowContext(context.Background(), `SELECT outbox_id FROM outbox`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return store, id
}

func outboxAttemptTime(t *testing.T, store *Store, id audit.OutboxID) time.Time {
	t.Helper()
	record, err := store.InspectOutbox(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return record.UpdatedAt.Add(time.Second)
}
