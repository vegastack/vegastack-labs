package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/ncruces/go-sqlite3"
)

type intentHandle struct {
	transaction *sql.Tx
	changed     bool
}

func (store *Store) Read(ctx context.Context, callback func(ReadTx) error) error {
	if callback == nil {
		return newStoreError("INPUT_INVALID", "database-read", false, nil)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyForRead(ctx); err != nil {
		return err
	}
	transaction, err := store.conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return store.transactionError(ctx, err)
	}
	defer func() { _ = transaction.Rollback() }()
	if err := callback(ReadTx{handle: transaction}); err != nil {
		if ctx.Err() != nil {
			return interruptedError("database-read", ctx.Err())
		}
		var sqliteError *sqlite3.Error
		if errors.As(err, &sqliteError) {
			return store.transactionError(ctx, err)
		}
		return err
	}
	if err := transaction.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		return store.transactionError(ctx, err)
	}
	return nil
}

func (store *Store) WriteIntent(ctx context.Context, expected *RevisionToken, callback func(IntentTx) error) (Commit, error) {
	if callback == nil {
		return Commit{}, newStoreError("INPUT_INVALID", "database-intent", false, nil)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyForTransaction(ctx); err != nil {
		return Commit{}, err
	}
	transaction, err := store.conn.BeginTx(ctx, nil)
	if err != nil {
		return Commit{}, store.transactionError(ctx, err)
	}
	defer func() { _ = transaction.Rollback() }()

	current, err := readRevision(ctx, transaction)
	if err != nil {
		return Commit{}, store.transactionError(ctx, err)
	}
	if expected != nil {
		if expected.RecoveryEpoch != current.RecoveryEpoch {
			return Commit{}, newStoreError("RECOVERY_EPOCH_MISMATCH", "database-revision", false, nil)
		}
		if expected.StateRevision != current.StateRevision {
			return Commit{}, newStoreError("STATE_CONFLICT", "database-revision", false, nil)
		}
	}
	handle := &intentHandle{transaction: transaction}
	if err := callback(IntentTx{handle: handle}); err != nil {
		if ctx.Err() != nil {
			return Commit{}, interruptedError("database-intent", ctx.Err())
		}
		if Code(err) == "INTEGRITY_FAILURE" {
			store.enterSafeMode("intent-failure")
		}
		return Commit{}, err
	}
	if ctx.Err() != nil {
		return Commit{}, interruptedError("database-intent", ctx.Err())
	}
	if !handle.changed {
		if err := transaction.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			return Commit{}, store.transactionError(ctx, err)
		}
		return Commit{Changed: false, StateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch}, nil
	}
	if err := store.checkIdentity(ctx); err != nil {
		return Commit{}, err
	}
	result, err := transaction.ExecContext(ctx, `UPDATE system_meta SET state_revision = state_revision + 1 WHERE id = 1 AND state_revision = ? AND recovery_epoch = ?`, current.StateRevision, current.RecoveryEpoch)
	if err != nil {
		return Commit{}, store.transactionError(ctx, err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		if err == nil {
			err = errors.New("revision guard did not match")
		}
		return Commit{}, newStoreError("STATE_CONFLICT", "database-revision", false, err)
	}
	if store.beforeCommit != nil {
		if err := store.beforeCommit(); err != nil {
			store.enterSafeMode("commit-failure")
			return Commit{}, databaseError("INTEGRITY_FAILURE", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		store.enterSafeMode("commit-failure")
		return Commit{}, store.transactionError(ctx, err)
	}
	current.StateRevision++
	store.health.Revision = current
	return Commit{Changed: true, StateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch}, nil
}

func (tx IntentTx) execChange(ctx context.Context, statement string, arguments ...any) (int64, error) {
	handle, ok := tx.handle.(*intentHandle)
	if !ok || handle == nil || handle.transaction == nil {
		return 0, newStoreError("INPUT_INVALID", "database-intent", false, nil)
	}
	result, err := handle.transaction.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return 0, classifySQLiteError(ctx, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, databaseError("INTEGRITY_FAILURE", err)
	}
	if rows > 0 {
		handle.changed = true
	}
	return rows, nil
}

func (tx ReadTx) queryRow(ctx context.Context, query string, arguments ...any) *sql.Row {
	transaction, _ := tx.handle.(*sql.Tx)
	return transaction.QueryRowContext(ctx, query, arguments...)
}

func (tx ReadTx) query(ctx context.Context, query string, arguments ...any) (*sql.Rows, error) {
	transaction, ok := tx.handle.(*sql.Tx)
	if !ok || transaction == nil {
		return nil, newStoreError("INPUT_INVALID", "database-read", false, nil)
	}
	return transaction.QueryContext(ctx, query, arguments...)
}

func (tx IntentTx) queryRow(ctx context.Context, query string, arguments ...any) *sql.Row {
	handle, _ := tx.handle.(*intentHandle)
	if handle == nil || handle.transaction == nil {
		return (&sql.Tx{}).QueryRowContext(ctx, query, arguments...)
	}
	return handle.transaction.QueryRowContext(ctx, query, arguments...)
}

func readRevision(ctx context.Context, transaction *sql.Tx) (RevisionToken, error) {
	var token RevisionToken
	err := transaction.QueryRowContext(ctx, `SELECT state_revision, recovery_epoch FROM system_meta WHERE id = 1`).Scan(&token.StateRevision, &token.RecoveryEpoch)
	return token, err
}

func (store *Store) readyForTransaction(ctx context.Context) error {
	if err := store.readyForRead(ctx); err != nil {
		return err
	}
	if store.health.Mode != DatabaseReady || !store.health.MutationEnabled {
		return newStoreError("PREREQUISITE_BLOCKED", "database-safe-mode", false, nil)
	}
	return nil
}

func (store *Store) readyForRead(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return interruptedError("database", err)
	}
	if store.closed {
		return newStoreError("DEPENDENCY_UNAVAILABLE", "database", false, nil)
	}
	return store.checkIdentity(ctx)
}

func (store *Store) transactionError(ctx context.Context, cause error) error {
	err := classifySQLiteError(ctx, cause)
	if Code(err) == "INTEGRITY_FAILURE" {
		store.enterSafeMode("transaction-failure")
	}
	return err
}

func classifySQLiteError(ctx context.Context, cause error) error {
	if ctx.Err() != nil || errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) || errors.Is(cause, sqlite3.INTERRUPT) {
		return interruptedError("database", cause)
	}
	if errors.Is(cause, sqlite3.BUSY) || errors.Is(cause, sqlite3.LOCKED) {
		return newStoreError("DEPENDENCY_UNAVAILABLE", "database", true, cause)
	}
	if errors.Is(cause, sqlite3.CONSTRAINT) {
		return newStoreError("STATE_CONFLICT", "database", false, cause)
	}
	return databaseError("INTEGRITY_FAILURE", cause)
}

func interruptedError(target string, cause error) error {
	return newStoreError("INTERRUPTED", target, false, cause)
}
