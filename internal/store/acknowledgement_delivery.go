package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// SaveMessageReceipt records a successful publication without granting approval
// authority or advancing the declaration revision. Replays preserve its binding.
func (repository *AcknowledgementRepository) SaveMessageReceipt(ctx context.Context, receipt acknowledgement.MessageReceipt) error {
	if receipt.Status == "" {
		receipt.Status = "pending"
	}
	if repository == nil || repository.store == nil || !validReceiptIdentifier(receipt.Destination, 256) || !validReceiptIdentifier(receipt.MessageID, 256) || !validReceiptIdentifier(receipt.PlanID, 128) || !audit.ValidFingerprint(audit.Fingerprint(receipt.PlanDigest)) || len(receipt.ReviewText) > 32768 || !utf8.ValidString(receipt.ReviewText) || strings.ContainsRune(receipt.ReviewText, 0) || receipt.Status != "pending" {
		return newStoreError(generated.ErrorCodeInputInvalid, "message-receipt", false, nil)
	}
	return repository.receiptTransaction(ctx, func(tx *sql.Tx) error {
		var digest string
		err := tx.QueryRowContext(ctx, `SELECT p.plan_digest FROM immutable_plans p JOIN acknowledgement_requests a ON a.plan_id=p.plan_id AND a.plan_digest=p.plan_digest WHERE p.plan_id=?`, receipt.PlanID).Scan(&digest)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && digest != receipt.PlanDigest) {
			return newStoreError(generated.ErrorCodePlanStale, "message-receipt", false, nil)
		}
		if err != nil {
			return err
		}
		var existing acknowledgement.MessageReceipt
		err = tx.QueryRowContext(ctx, `SELECT plan_id,plan_digest,review_text FROM acknowledgement_deliveries WHERE destination=? AND message_id=?`, receipt.Destination, receipt.MessageID).Scan(&existing.PlanID, &existing.PlanDigest, &existing.ReviewText)
		if err == nil {
			if existing.PlanID != receipt.PlanID || existing.PlanDigest != receipt.PlanDigest || existing.ReviewText != receipt.ReviewText {
				return newStoreError(generated.ErrorCodeStateConflict, "message-receipt", false, nil)
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO acknowledgement_deliveries(destination,message_id,plan_id,plan_digest,review_text,status,created_at) VALUES(?,?,?,?,?,'pending',?)`, receipt.Destination, receipt.MessageID, receipt.PlanID, receipt.PlanDigest, receipt.ReviewText, repository.store.config.Clock().UTC().Format(time.RFC3339))
		return err
	})
}

// MessageReceipts returns only messages that still need lifecycle projection.
func (repository *AcknowledgementRepository) MessageReceipts(ctx context.Context) ([]acknowledgement.MessageReceipt, error) {
	if repository == nil || repository.store == nil {
		return nil, newStoreError(generated.ErrorCodeInputInvalid, "message-receipt", false, nil)
	}
	receipts := []acknowledgement.MessageReceipt{}
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		rows, err := tx.query(ctx, `SELECT destination,message_id,plan_id,plan_digest,review_text,status FROM acknowledgement_deliveries WHERE completed_at IS NULL ORDER BY destination,message_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r acknowledgement.MessageReceipt
			if err := rows.Scan(&r.Destination, &r.MessageID, &r.PlanID, &r.PlanDigest, &r.ReviewText, &r.Status); err != nil {
				return err
			}
			receipts = append(receipts, r)
		}
		return rows.Err()
	})
	return receipts, err
}

func (repository *AcknowledgementRepository) CompleteMessageReceipt(ctx context.Context, destination, messageID, status string) error {
	terminal := false
	switch status {
	case "pending", "approved", "queued", "running", "interrupted":
	case "succeeded", "rejected", "expired", "stale", "failed", "partial", "cancelled":
		terminal = true
	default:
		return newStoreError(generated.ErrorCodeInputInvalid, "message-receipt", false, nil)
	}
	if repository == nil || repository.store == nil || !validReceiptIdentifier(destination, 256) || !validReceiptIdentifier(messageID, 256) {
		return newStoreError(generated.ErrorCodeInputInvalid, "message-receipt", false, nil)
	}
	return repository.receiptTransaction(ctx, func(tx *sql.Tx) error {
		var oldStatus string
		var completed sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT status,completed_at FROM acknowledgement_deliveries WHERE destination=? AND message_id=?`, destination, messageID).Scan(&oldStatus, &completed)
		if errors.Is(err, sql.ErrNoRows) {
			return newStoreError(generated.ErrorCodeResourceNotFound, "message-receipt", false, nil)
		}
		if err != nil {
			return err
		}
		if oldStatus == status {
			return nil
		}
		if completed.Valid {
			return newStoreError(generated.ErrorCodeStateConflict, "message-receipt", false, nil)
		}
		var completedAt any
		if terminal {
			completedAt = repository.store.config.Clock().UTC().Format(time.RFC3339)
		}
		_, err = tx.ExecContext(ctx, `UPDATE acknowledgement_deliveries SET status=?,completed_at=? WHERE destination=? AND message_id=?`, status, completedAt, destination, messageID)
		return err
	})
}

func validReceiptIdentifier(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for _, r := range value {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}

func (repository *AcknowledgementRepository) receiptTransaction(ctx context.Context, business func(*sql.Tx) error) error {
	store := repository.store
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyForTransaction(ctx); err != nil {
		return err
	}
	tx, err := store.conn.BeginTx(ctx, nil)
	if err != nil {
		return store.transactionError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := business(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return store.transactionError(ctx, err)
	}
	return nil
}
