//go:build linux

package store

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
)

func TestWriteIntentCommitsOnceAndNoopDoesNotAdvance(t *testing.T) {
	store := openTestStore(t)
	createIntentFixtureTable(t, store)
	expected := RevisionToken{StateRevision: 0, RecoveryEpoch: 0}
	commit, err := store.WriteIntent(context.Background(), &expected, func(tx IntentTx) error {
		_, err := tx.execChange(context.Background(), `INSERT INTO intent_fixture(id) VALUES (?)`, "one")
		return err
	})
	if err != nil || commit != (Commit{Changed: true, StateRevision: 1, RecoveryEpoch: 0}) {
		t.Fatalf("commit = %#v, %v", commit, err)
	}
	noop, err := store.WriteIntent(context.Background(), nil, func(IntentTx) error { return nil })
	if err != nil || noop != (Commit{Changed: false, StateRevision: 1, RecoveryEpoch: 0}) {
		t.Fatalf("noop = %#v, %v", noop, err)
	}
	_, err = store.WriteIntent(context.Background(), &expected, func(IntentTx) error {
		t.Fatal("stale callback ran")
		return nil
	})
	if Code(err) != "STATE_CONFLICT" {
		t.Fatalf("stale code = %q", Code(err))
	}
}

func TestWriteIntentRollsBackAndChecksEpochBeforeCallback(t *testing.T) {
	store := openTestStore(t)
	createIntentFixtureTable(t, store)
	sentinel := errors.New("callback failed")
	_, err := store.WriteIntent(context.Background(), nil, func(tx IntentTx) error {
		if _, err := tx.execChange(context.Background(), `INSERT INTO intent_fixture(id) VALUES (?)`, "rollback"); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("callback error = %v", err)
	}
	assertIntentRows(t, store, 0)
	wrongEpoch := RevisionToken{RecoveryEpoch: 1}
	_, err = store.WriteIntent(context.Background(), &wrongEpoch, func(IntentTx) error {
		t.Fatal("epoch-mismatch callback ran")
		return nil
	})
	if Code(err) != "RECOVERY_EPOCH_MISMATCH" {
		t.Fatalf("epoch code = %q", Code(err))
	}
}

func TestWriteIntentConstraintCancellationAndCommitFailure(t *testing.T) {
	store := openTestStore(t)
	createIntentFixtureTable(t, store)
	_, err := store.WriteIntent(context.Background(), nil, func(tx IntentTx) error {
		_, err := tx.execChange(context.Background(), `INSERT INTO intent_fixture(id) VALUES (NULL)`)
		return err
	})
	if Code(err) != "STATE_CONFLICT" {
		t.Fatalf("constraint code = %q", Code(err))
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.WriteIntent(cancelled, nil, func(IntentTx) error { return nil }); Code(err) != "INTERRUPTED" {
		t.Fatalf("cancellation code = %q", Code(err))
	}
	store.beforeCommit = func() error { return errors.New("injected commit failure") }
	if _, err := store.WriteIntent(context.Background(), nil, func(tx IntentTx) error {
		_, err := tx.execChange(context.Background(), `INSERT INTO intent_fixture(id) VALUES (?)`, "failed")
		return err
	}); Code(err) != "INTEGRITY_FAILURE" {
		t.Fatalf("commit-failure code = %q", Code(err))
	}
	if got := store.health.Mode; got != DatabaseSafeMode {
		t.Fatalf("mode = %q", got)
	}
	assertIntentRows(t, store, 0)
}

func TestWriteIntentSerializesConcurrentCallers(t *testing.T) {
	store := openTestStore(t)
	createIntentFixtureTable(t, store)
	var wait sync.WaitGroup
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, err := store.WriteIntent(context.Background(), nil, func(tx IntentTx) error {
				_, err := tx.execChange(context.Background(), `INSERT INTO intent_fixture(id) VALUES (?)`, index)
				return err
			})
			if err != nil {
				t.Errorf("write %d: %v", index, err)
			}
		}(index)
	}
	wait.Wait()
	assertIntentRows(t, store, 8)
	if store.health.Revision.StateRevision != 8 {
		t.Fatalf("state revision = %d", store.health.Revision.StateRevision)
	}
}

func TestReadUsesSnapshotAndRollsBack(t *testing.T) {
	store := openTestStore(t)
	createIntentFixtureTable(t, store)
	if err := store.Read(context.Background(), func(tx ReadTx) error {
		var revision int64
		return tx.queryRow(context.Background(), `SELECT state_revision FROM system_meta WHERE id = 1`).Scan(&revision)
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Read(context.Background(), func(ReadTx) error { return errors.New("stop") }); err == nil {
		t.Fatal("callback error was discarded")
	}
}

func TestBusyBeforeBeginIsRetryableWithoutCallback(t *testing.T) {
	store := openTestStore(t)
	contender, err := sql.Open(sqliteDriverName, sqliteURI(store.config.DatabasePath))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = contender.Close() })
	if _, err := contender.ExecContext(context.Background(), `PRAGMA busy_timeout = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := contender.ExecContext(context.Background(), `BEGIN EXCLUSIVE`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = contender.ExecContext(context.Background(), `ROLLBACK`) })
	_, err = store.WriteIntent(context.Background(), nil, func(IntentTx) error {
		t.Fatal("busy callback ran")
		return nil
	})
	var storeError *StoreError
	if !errors.As(err, &storeError) || Code(err) != "DEPENDENCY_UNAVAILABLE" || !storeError.Retryable() {
		t.Fatalf("busy error = %v", err)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(context.Background(), testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func createIntentFixtureTable(t *testing.T, store *Store) {
	t.Helper()
	if _, err := store.conn.ExecContext(context.Background(), `CREATE TABLE intent_fixture(id ANY PRIMARY KEY NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
}

func assertIntentRows(t *testing.T, store *Store, expected int) {
	t.Helper()
	var count int
	if err := store.conn.QueryRowContext(context.Background(), `SELECT count(*) FROM intent_fixture`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != expected {
		t.Fatalf("row count = %d, want %d", count, expected)
	}
}
