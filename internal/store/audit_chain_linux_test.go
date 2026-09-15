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
