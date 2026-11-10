package store

import (
	"context"
	"database/sql"
	"errors"
)

// A Store owns one SQL connection for its lifetime. database/sql discards that
// connection when a transaction's context is canceled because this driver does
// not implement session reset/validation. Keep transaction cleanup under Store
// ownership; individual SQL statements still use the caller's context.
func beginTransaction(ctx context.Context, conn *sql.Conn, options *sql.TxOptions) (*sql.Tx, error) {
	if err := ctx.Err(); err != nil {
		return nil, interruptedError("database-transaction", err)
	}
	tx, err := conn.BeginTx(context.WithoutCancel(ctx), options)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		if rollback := tx.Rollback(); rollback != nil && !errors.Is(rollback, sql.ErrTxDone) {
			return nil, rollback
		}
		return nil, interruptedError("database-transaction", err)
	}
	return tx, nil
}

// Never begin a commit after the caller has canceled. A real commit error is
// returned unchanged so existing uncertainty/safe-mode handling is preserved.
func commitTransaction(ctx context.Context, tx *sql.Tx) error {
	if err := ctx.Err(); err != nil {
		if rollback := tx.Rollback(); rollback != nil && !errors.Is(rollback, sql.ErrTxDone) {
			return rollback
		}
		return interruptedError("database-transaction", err)
	}
	return tx.Commit()
}
