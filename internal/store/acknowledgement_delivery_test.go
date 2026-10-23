//go:build linux

package store

import (
	"context"
	"reflect"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestMessageReceiptSurvivesRestartWithoutGrantingAuthority(t *testing.T) {
	ctx := context.Background()
	config := testConfig(t)
	s, err := Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	plan := seedAcknowledgementPlan(t, s)
	repo := NewAcknowledgementRepository(s)
	if _, _, err := repo.Create(ctx, acknowledgementTestCreate(plan)); err != nil {
		t.Fatal(err)
	}
	var before RevisionToken
	if err := s.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&before.StateRevision, &before.RecoveryEpoch)
	}); err != nil {
		t.Fatal(err)
	}
	receipt := acknowledgement.MessageReceipt{Destination: "synthetic-channel", MessageID: "1234567890.123456", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, ReviewText: "Synthetic nonsecret review"}
	bad := receipt
	bad.PlanDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := repo.SaveMessageReceipt(ctx, bad); Code(err) != generated.ErrorCodePlanStale {
		t.Fatalf("digest mismatch = %v", err)
	}
	if err := repo.SaveMessageReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveMessageReceipt(ctx, receipt); err != nil {
		t.Fatalf("exact replay = %v", err)
	}
	bad = receipt
	bad.ReviewText = "changed binding"
	if err := repo.SaveMessageReceipt(ctx, bad); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("rebound message = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	config.Mode = OpenExisting
	s, err = Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	repo = NewAcknowledgementRepository(s)
	receipt.Status = "pending"
	rows, err := repo.MessageReceipts(ctx)
	if err != nil || !reflect.DeepEqual(rows, []acknowledgement.MessageReceipt{receipt}) {
		t.Fatalf("restart receipts = %#v, %v", rows, err)
	}
	stored, err := repo.Get(ctx, plan.PlanID)
	if err != nil || stored.Acknowledgement.Status != "pending" || stored.Consumed {
		t.Fatalf("receipt changed authority: %#v, %v", stored, err)
	}
	if err := repo.CompleteMessageReceipt(ctx, receipt.Destination, receipt.MessageID, "approved"); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"interrupted", "running"} {
		if err := repo.CompleteMessageReceipt(ctx, receipt.Destination, receipt.MessageID, status); err != nil {
			t.Fatal(err)
		}
		active, err := repo.MessageReceipts(ctx)
		if err != nil || len(active) != 1 || active[0].Status != status {
			t.Fatalf("resumable receipt: %#v, %v", active, err)
		}
	}
	if err := repo.CompleteMessageReceipt(ctx, receipt.Destination, receipt.MessageID, "succeeded"); err != nil {
		t.Fatal(err)
	}
	if err := repo.CompleteMessageReceipt(ctx, receipt.Destination, receipt.MessageID, "succeeded"); err != nil {
		t.Fatalf("completion replay = %v", err)
	}
	if err := repo.CompleteMessageReceipt(ctx, receipt.Destination, receipt.MessageID, "running"); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("terminal revival = %v", err)
	}
	rows, err = repo.MessageReceipts(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("completed receipt active = %#v, %v", rows, err)
	}
	var after RevisionToken
	if err := s.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&after.StateRevision, &after.RecoveryEpoch)
	}); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("presentation changed revision: %#v -> %#v", before, after)
	}
	var status string
	if err := s.conn.QueryRowContext(ctx, `SELECT status FROM acknowledgement_deliveries WHERE destination=? AND message_id=?`, receipt.Destination, receipt.MessageID).Scan(&status); err != nil || status != "succeeded" {
		t.Fatalf("terminal receipt missing: %q, %v", status, err)
	}
	if _, err := s.conn.ExecContext(ctx, `UPDATE acknowledgement_deliveries SET review_text='tampered'`); err == nil {
		t.Fatal("durable binding mutable")
	}
}
