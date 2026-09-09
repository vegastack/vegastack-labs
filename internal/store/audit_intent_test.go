//go:build linux

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func TestWriteIntentCommitsBusinessEventAndRequiredOutboxExactlyOnce(t *testing.T) {
	store := openAuditTestStore(t)
	req := publicIntentRequest(t, "1", []audit.OutboxRequirement{{Destination: "primary-audit", Enabled: true}, {Destination: "secondary-audit", Enabled: false}})
	first, err := store.writeIntent(context.Background(), req, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_business(id) VALUES('business-test-1')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	retry, err := store.writeIntent(context.Background(), req, func(context.Context, *sql.Tx) error {
		t.Fatal("replay callback ran")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created || retry.Created || first.EventID != retry.EventID || first.Commit.StateRevision != 1 || retry.Commit.StateRevision != 1 {
		t.Fatalf("first/retry = %#v / %#v", first, retry)
	}
	assertAuditCounts(t, store, map[string]int{"audit_business": 1, "audit_events": 1, "intent_keys": 1, "outbox": 2})
	assertOutboxStatuses(t, store, map[string]audit.OutboxStatus{"primary-audit": audit.OutboxPending, "secondary-audit": audit.OutboxPaused})
}

func TestWriteIntentFaultMatrixRollsBackEveryLayer(t *testing.T) {
	for _, stage := range []auditIntentStage{auditAfterBusiness, auditAfterRevision, auditAfterSequence, auditAfterEvent, auditAfterIntent, auditAfterOutbox, auditBeforeCommit} {
		t.Run(string(stage), func(t *testing.T) {
			store := openAuditTestStore(t)
			store.auditFault = func(got auditIntentStage) error {
				if got == stage {
					return errors.New("synthetic audit fault")
				}
				return nil
			}
			_, err := store.writeIntent(context.Background(), publicIntentRequest(t, "2", twoDestinations()), insertSyntheticBusiness)
			if err == nil {
				t.Fatal("injected failure succeeded")
			}
			assertAuditCounts(t, store, map[string]int{"audit_business": 0, "audit_events": 0, "intent_keys": 0, "outbox": 0})
			if got := readRevisionAndSequence(t, store); got != (revisionAndSequence{}) {
				t.Fatalf("state = %#v", got)
			}
		})
	}
}

func TestWriteIntentRejectsConflictInvalidReferencesAndWrongCorrectionTarget(t *testing.T) {
	store := openAuditTestStore(t)
	first, err := store.writeIntent(context.Background(), publicIntentRequest(t, "3", nil), insertSyntheticBusiness)
	if err != nil {
		t.Fatal(err)
	}
	mismatch := publicIntentRequest(t, "3", nil)
	mismatch.Idempotency.RequestDigest = fingerprint("d")
	if _, err := store.writeIntent(context.Background(), mismatch, insertSyntheticBusiness); Code(err) != "STATE_CONFLICT" {
		t.Fatalf("mismatch code = %q", Code(err))
	}
	invalid := publicIntentRequest(t, "4", nil)
	unknown := audit.EventID(99)
	invalid.Event.CausationID = &unknown
	if _, err := store.writeIntent(context.Background(), invalid, insertSyntheticBusiness); Code(err) != "STATE_CONFLICT" {
		t.Fatalf("causation code = %q", Code(err))
	}
	wrong := publicIntentRequest(t, "5", nil)
	wrong.Event.CorrectionOf = &first.EventID
	wrong.Event.Target.ID = "other-target"
	if _, err := store.writeIntent(context.Background(), wrong, insertSyntheticBusiness); Code(err) != "STATE_CONFLICT" {
		t.Fatalf("correction code = %q", Code(err))
	}
	assertAuditCounts(t, store, map[string]int{"audit_business": 1, "audit_events": 1, "intent_keys": 1})
}

func TestWriteIntentAcceptsEarlierSameTargetCorrectionAndRejectsStaleRevision(t *testing.T) {
	store := openAuditTestStore(t)
	first, err := store.writeIntent(context.Background(), publicIntentRequest(t, "6", nil), insertSyntheticBusiness)
	if err != nil {
		t.Fatal(err)
	}
	correction := publicIntentRequest(t, "7", nil)
	correction.Event.CorrectionOf = &first.EventID
	correction.Event.Target = publicIntentRequest(t, "6", nil).Event.Target
	correction.Expected = &RevisionToken{StateRevision: 1, RecoveryEpoch: 0}
	if _, err := store.writeIntent(context.Background(), correction, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_business(id) VALUES('business-test-2')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	stale := publicIntentRequest(t, "8", nil)
	stale.Expected = &RevisionToken{StateRevision: 1, RecoveryEpoch: 0}
	if _, err := store.writeIntent(context.Background(), stale, insertSyntheticBusiness); Code(err) != "STATE_CONFLICT" {
		t.Fatalf("stale code = %q", Code(err))
	}
	if got := readRevisionAndSequence(t, store); got != (revisionAndSequence{StateRevision: 2, AuditSequence: 2}) {
		t.Fatalf("state = %#v", got)
	}
}

func TestWriteIntentCancellationAndCommitUncertaintyFailClosed(t *testing.T) {
	t.Run("cancelled", func(t *testing.T) {
		store := openAuditTestStore(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := store.writeIntent(ctx, publicIntentRequest(t, "9", nil), insertSyntheticBusiness); Code(err) != "INTERRUPTED" {
			t.Fatalf("cancel code = %q", Code(err))
		}
		assertAuditCounts(t, store, map[string]int{"audit_business": 0, "audit_events": 0})
	})
	t.Run("after commit", func(t *testing.T) {
		store := openAuditTestStore(t)
		store.auditFault = func(stage auditIntentStage) error {
			if stage == auditAfterCommit {
				return errors.New("synthetic lost reply")
			}
			return nil
		}
		if _, err := store.writeIntent(context.Background(), publicIntentRequest(t, "a", nil), insertSyntheticBusiness); Code(err) != "INTEGRITY_FAILURE" {
			t.Fatalf("uncertain code = %q", Code(err))
		}
		if store.health.Mode != DatabaseSafeMode || store.health.MutationEnabled {
			t.Fatalf("health = %#v", store.health)
		}
		assertAuditCounts(t, store, map[string]int{"audit_business": 1, "audit_events": 1, "intent_keys": 1})
	})
}

func TestConcurrentAuditWritersProduceOneStrictSequence(t *testing.T) {
	store := openAuditTestStore(t)
	const writers = 12
	var wait sync.WaitGroup
	errorsByWriter := make(chan error, writers)
	for index := 0; index < writers; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			req := publicIntentRequest(t, fmt.Sprintf("%x", index), nil)
			req.Event.Target.ID = fmt.Sprintf("target-%d", index)
			_, err := store.writeIntent(context.Background(), req, func(ctx context.Context, tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, `INSERT INTO audit_business(id) VALUES(?)`, fmt.Sprintf("business-%d", index))
				return err
			})
			errorsByWriter <- err
		}()
	}
	wait.Wait()
	close(errorsByWriter)
	for err := range errorsByWriter {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count, minimum, maximum int
	if err := store.conn.QueryRowContext(context.Background(), `SELECT count(*),min(event_id),max(event_id) FROM audit_events`).Scan(&count, &minimum, &maximum); err != nil {
		t.Fatal(err)
	}
	if count != writers || minimum != 1 || maximum != writers {
		t.Fatalf("sequence count/min/max = %d/%d/%d", count, minimum, maximum)
	}
}

func TestConcurrentBusinessAndOperationalWritersShareOneStrictSequence(t *testing.T) {
	store := openAuditTestStore(t)
	const writers = 16
	start := make(chan struct{})
	errorsByWriter := make(chan error, writers)
	var wait sync.WaitGroup
	for index := range writers {
		index := index
		event := publicIntentRequest(t, "f", nil).Event
		event.CorrelationID = fmt.Sprintf("request-mixed-%d", index)
		event.Target.ID = fmt.Sprintf("target-mixed-%d", index)
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			key := digestForText(fmt.Sprintf("mixed-key-%d", index))
			requestDigest := digestForText(fmt.Sprintf("mixed-request-%d", index))
			if index%2 == 0 {
				_, err := store.writeIntent(context.Background(), intentRequest{Idempotency: audit.IntentKey{Scope: "mixed-business", KeyDigest: key, RequestDigest: requestDigest}, Event: event}, func(ctx context.Context, tx *sql.Tx) error {
					_, err := tx.ExecContext(ctx, `INSERT INTO audit_business(id) VALUES(?)`, fmt.Sprintf("business-mixed-%d", index))
					return err
				})
				errorsByWriter <- err
				return
			}
			for {
				health, err := store.Health(context.Background())
				if err != nil {
					errorsByWriter <- err
					return
				}
				_, err = store.AppendOperationalAudit(context.Background(), OperationalAuditRequest{Expected: health.Revision, Idempotency: audit.IntentKey{Scope: "mixed-operational", KeyDigest: key, RequestDigest: requestDigest}, Event: event})
				if Code(err) == "STATE_CONFLICT" {
					continue
				}
				errorsByWriter <- err
				return
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errorsByWriter)
	for err := range errorsByWriter {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := readRevisionAndSequence(t, store); got != (revisionAndSequence{StateRevision: writers / 2, AuditSequence: writers}) {
		t.Fatalf("mixed state = %#v", got)
	}
	assertEventSequenceConsistent(t, store)
}

func openAuditTestStore(t *testing.T) *Store {
	t.Helper()
	store := openTestStore(t)
	if _, err := store.conn.ExecContext(context.Background(), `CREATE TABLE audit_business(id TEXT PRIMARY KEY) STRICT`); err != nil {
		t.Fatal(err)
	}
	return store
}

func publicIntentRequest(t *testing.T, fill string, destinations []audit.OutboxRequirement) intentRequest {
	t.Helper()
	if len(fill) != 1 {
		t.Fatal("fixture fill must be one byte")
	}
	attribution, err := audit.NewAttribution(identity.Principal{ID: "principal-test-1", Method: identity.LocalOSPeerMethod}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return intentRequest{
		Idempotency:  audit.IntentKey{Scope: "test-intent", KeyDigest: fingerprint(fill), RequestDigest: fingerprint(fill)},
		Event:        audit.EventDraft{Type: "test.intent.persisted", CorrelationID: "request-test-" + fill, Attribution: attribution, Target: audit.Target{Kind: "test-target", ID: "target-test-" + fill}},
		Destinations: destinations,
	}
}

func fingerprint(fill string) audit.Fingerprint {
	return audit.Fingerprint("sha256:" + strings.Repeat(fill, 64))
}

func twoDestinations() []audit.OutboxRequirement {
	return []audit.OutboxRequirement{{Destination: "primary-audit", Enabled: true}, {Destination: "secondary-audit", Enabled: true}}
}

func insertSyntheticBusiness(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_business(id) VALUES('business-test-1')`)
	return err
}

type revisionAndSequence struct {
	StateRevision int64
	AuditSequence int64
}

func readRevisionAndSequence(t *testing.T, store *Store) revisionAndSequence {
	t.Helper()
	var got revisionAndSequence
	if err := store.conn.QueryRowContext(context.Background(), `SELECT state_revision,audit_sequence FROM system_meta WHERE id=1`).Scan(&got.StateRevision, &got.AuditSequence); err != nil {
		t.Fatal(err)
	}
	return got
}

func assertAuditCounts(t *testing.T, store *Store, expected map[string]int) {
	t.Helper()
	for table, want := range expected {
		var got int
		if err := store.conn.QueryRowContext(context.Background(), `SELECT count(*) FROM `+table).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s rows = %d, want %d", table, got, want)
		}
	}
}

func assertOutboxStatuses(t *testing.T, store *Store, expected map[string]audit.OutboxStatus) {
	t.Helper()
	rows, err := store.conn.QueryContext(context.Background(), `SELECT destination_id,status FROM outbox ORDER BY destination_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var destination string
		var status audit.OutboxStatus
		if err := rows.Scan(&destination, &status); err != nil {
			t.Fatal(err)
		}
		if expected[destination] != status {
			t.Fatalf("%s status = %q", destination, status)
		}
		delete(expected, destination)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(expected) != 0 {
		t.Fatalf("missing destinations: %v", expected)
	}
}
