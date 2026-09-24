//go:build linux

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/audit"
)

func chainTestIntent(t *testing.T, index int) intentRequest {
	t.Helper()
	request := publicIntentRequest(t, "a", nil)
	digest := sha256.Sum256([]byte(fmt.Sprintf("audit-chain-writer-%d", index)))
	key := audit.Fingerprint(fmt.Sprintf("sha256:%x", digest))
	request.Idempotency = audit.IntentKey{Scope: "chain-test-intent", KeyDigest: key, RequestDigest: key}
	request.Event.CorrelationID = fmt.Sprintf("chain-test-%d", index)
	request.Event.Target.ID = fmt.Sprintf("chain-target-%d", index)
	return request
}

func TestConcurrentAuditIntentsCannotForkChain(t *testing.T) {
	authority := openAuditTestStore(t)
	const writers = 32
	var wait sync.WaitGroup
	results := make(chan error, writers)
	for index := range writers {
		request := chainTestIntent(t, index)
		businessID := fmt.Sprintf("chain-business-%d", index)
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := authority.writeIntent(context.Background(), request, func(ctx context.Context, tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, `INSERT INTO audit_business(id) VALUES(?)`, businessID)
				return err
			})
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	rows, err := authority.conn.QueryContext(context.Background(), `SELECT event_id,segment_sequence,previous_digest,link_digest,instance_id,recovery_epoch FROM audit_chain_links ORDER BY event_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	var previous audit.Fingerprint
	var instanceID string
	for rows.Next() {
		var eventID audit.EventID
		var sequence, epoch int64
		var predecessor, digest audit.Fingerprint
		var instance string
		if err := rows.Scan(&eventID, &sequence, &predecessor, &digest, &instance, &epoch); err != nil {
			t.Fatal(err)
		}
		count++
		if eventID != audit.EventID(count) || sequence != int64(count) || epoch != 0 || instance == "" || !audit.ValidFingerprint(digest) || !audit.ValidFingerprint(predecessor) {
			t.Fatalf("unbound chain row %d: event=%d sequence=%d epoch=%d instance=%q", count, eventID, sequence, epoch, instance)
		}
		if count > 1 && (predecessor != previous || instance != instanceID) {
			t.Fatalf("fork or instance swap at event %d", eventID)
		}
		previous, instanceID = digest, instance
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != writers {
		t.Fatalf("chain links = %d, want %d", count, writers)
	}
}

func TestAuditIntentRollbackCannotLeaveOrphanLink(t *testing.T) {
	authority := openAuditTestStore(t)
	authority.auditFault = func(stage auditIntentStage) error {
		if stage == auditAfterIntent {
			return errors.New("synthetic pre-commit interruption")
		}
		return nil
	}
	if _, err := authority.writeIntent(context.Background(), chainTestIntent(t, 0), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_business(id) VALUES('chain-business-0')`)
		return err
	}); err == nil {
		t.Fatal("injected rollback unexpectedly committed")
	}
	var links, events int
	if err := authority.conn.QueryRowContext(context.Background(), `SELECT count(*) FROM audit_chain_links`).Scan(&links); err != nil {
		t.Fatal(err)
	}
	if err := authority.conn.QueryRowContext(context.Background(), `SELECT count(*) FROM audit_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if links != 0 || events != 0 {
		t.Fatalf("orphan link after rollback: links=%d events=%d", links, events)
	}
}

func TestRecoveryEpochMustBindPriorCheckpointAndDecisionBeforeAppend(t *testing.T) {
	t.Run("missing binding fails closed", func(t *testing.T) {
		authority := openAuditTestStore(t)
		if _, err := authority.conn.ExecContext(context.Background(), `UPDATE system_meta SET recovery_epoch=1 WHERE id=1`); err != nil {
			t.Fatal(err)
		}
		if _, err := authority.writeIntent(context.Background(), chainTestIntent(t, 0), insertSyntheticBusiness); err == nil {
			t.Fatal("unbound recovery epoch accepted an audit event")
		}
		if authority.health.Mode != DatabaseSafeMode || authority.health.MutationEnabled {
			t.Fatalf("unbound recovery epoch did not fail closed: %#v", authority.health)
		}
	})
	t.Run("bound epoch continues from explicit recovery inputs", func(t *testing.T) {
		authority := openAuditTestStore(t)
		prior, decision := fingerprint("a"), fingerprint("b")
		if err := authority.PrepareRecoveryAuditEpoch(context.Background(), 1, prior, decision); err != nil {
			t.Fatal(err)
		}
		if _, err := authority.conn.ExecContext(context.Background(), `UPDATE system_meta SET recovery_epoch=1 WHERE id=1`); err != nil {
			t.Fatal(err)
		}
		if _, err := authority.writeIntent(context.Background(), chainTestIntent(t, 1), insertSyntheticBusiness); err != nil {
			t.Fatal(err)
		}
		var gotPrior, gotDecision audit.Fingerprint
		if err := authority.conn.QueryRowContext(context.Background(), `SELECT prior_checkpoint_digest,recovery_decision_digest FROM audit_epoch_genesis WHERE recovery_epoch=1`).Scan(&gotPrior, &gotDecision); err != nil {
			t.Fatal(err)
		}
		if gotPrior != prior || gotDecision != decision {
			t.Fatalf("genesis inputs = %q / %q", gotPrior, gotDecision)
		}
	})
}

func TestAuditChainStoresReconstructableContext(t *testing.T) {
	authority := openAuditTestStore(t)
	_, err := authority.writeIntent(context.Background(), chainTestIntent(t, 0), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_business(id) VALUES('chain-context-business')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var contextBytes []byte
	var contextDigest audit.Fingerprint
	if err := authority.conn.QueryRowContext(context.Background(), `SELECT context_bytes,context_digest FROM audit_chain_links WHERE event_id=1`).Scan(&contextBytes, &contextDigest); err != nil {
		t.Fatal(err)
	}
	wantBytes, wantDigest, err := audit.CanonicalContext(audit.ContextIDs{})
	if err != nil {
		t.Fatal(err)
	}
	if string(contextBytes) != string(wantBytes) || contextDigest != wantDigest {
		t.Fatal("stored chain context cannot be independently reconstructed")
	}
}

func TestReadAuditSuffixReturnsOnlyCanonicalBoundedEvidence(t *testing.T) {
	authority := openAuditTestStore(t)
	for index := range 3 {
		if _, err := authority.writeIntent(context.Background(), chainTestIntent(t, index), insertSyntheticBusiness); err != nil {
			t.Fatal(err)
		}
	}
	suffix, err := authority.ReadAuditSuffix(context.Background(), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(suffix.Events) != 2 || len(suffix.Chain.Links) != 2 || suffix.Events[0].EventID != 2 || suffix.Events[1].EventID != 3 || !audit.ValidFingerprint(suffix.Digest) {
		t.Fatalf("suffix=%#v", suffix)
	}
	if _, err := authority.ReadAuditSuffix(context.Background(), 1, MaxRecoveryAuditSuffixEvents+1); err == nil {
		t.Fatal("unbounded audit suffix accepted")
	}
}
