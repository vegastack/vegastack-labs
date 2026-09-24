//go:build linux

package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func TestCheckpointTransitionsRequireIndependentSettlement(t *testing.T) {
	authority := openAuditTestStore(t)
	request := chainTestIntent(t, 0)
	if _, err := authority.writeIntent(context.Background(), request, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_business(id) VALUES('checkpoint-business')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	chain, err := authority.ChainRange(context.Background(), 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	current, err := NewPlanRepository(authority).CurrentRevision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := generated.AuditCheckpoint{Schema: generated.SchemaIDAuditCheckpoint, SchemaVersion: "1.1.0", CheckpointID: "checkpoint-a", FirstEventID: 1, LastEventID: 1, ChainDigest: string(chain.RangeDigest), InstanceID: chain.Links[0].InstanceID, FirstSegmentSequence: 1, LastSegmentSequence: 1, SignerReferenceID: "signer-a", SignerMaterialVersion: "version-a", Status: "pending", ReasonCode: "awaiting-signature", PreAnchor: false, SourceKind: "local", ProofClass: "fixture", VerificationStatus: "pending", RecoveryEpoch: 0}
	attribution := request.Event.Attribution
	created, err := authority.CreatePendingCheckpoint(context.Background(), CheckpointCreateRequest{Checkpoint: checkpoint, ExactPath: "audit-anchor/checkpoint-a.json.enc", Expected: current, KeyDigest: digestForText("checkpoint-create-key"), RequestDigest: digestForText("checkpoint-create-request"), Attribution: attribution})
	if err != nil || created.Status != "pending" {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 16, 8, 0, 0, 0, time.UTC)
	signed, err := authority.RecordCheckpointSignature(context.Background(), CheckpointSignatureRequest{CheckpointID: checkpoint.CheckpointID, PublicKeyID: "key-a", ExactPath: "audit-anchor/checkpoint-a.json.enc", SignatureDigest: digestForText("signature"), PayloadDigest: digestForText("payload"), EncryptedPayload: []byte("encrypted-fixture"), At: now, KeyDigest: digestForText("checkpoint-sign-key"), RequestDigest: digestForText("checkpoint-sign-request"), Attribution: attribution})
	if err != nil || signed.Status != "signed" {
		t.Fatal(err)
	}
	exported, err := authority.RecordCheckpointExport(context.Background(), CheckpointExportRequest{CheckpointID: checkpoint.CheckpointID, ReceiptDigest: digestForText("receipt"), At: now.Add(time.Second), KeyDigest: digestForText("checkpoint-export-key"), RequestDigest: digestForText("checkpoint-export-request"), Attribution: attribution})
	if err != nil || exported.Status != "export-pending" {
		t.Fatal(err)
	}
	if exported.IndependentReadDigest != nil {
		t.Fatal("unconfirmed checkpoint marked independent")
	}
	anchored, err := authority.SettleCheckpoint(context.Background(), CheckpointSettleRequest{CheckpointID: checkpoint.CheckpointID, IndependentDigest: digestForText("independent"), At: now.Add(2 * time.Second), KeyDigest: digestForText("checkpoint-settle-key"), RequestDigest: digestForText("checkpoint-settle-request"), Attribution: attribution})
	if err != nil || anchored.Status != "anchored" || anchored.IndependentReadDigest == nil {
		t.Fatal(err)
	}
	if _, err := authority.SettleCheckpoint(context.Background(), CheckpointSettleRequest{CheckpointID: checkpoint.CheckpointID, IndependentDigest: digestForText("different"), At: now.Add(3 * time.Second), KeyDigest: digestForText("checkpoint-settle-other-key"), RequestDigest: digestForText("checkpoint-settle-other-request"), Attribution: attribution}); err == nil {
		t.Fatal("anchored checkpoint settled twice")
	}
}

func TestScopedAuditCheckpointPageFiltersPartialGrantAndRejectsRevocation(t *testing.T) {
	ctx := context.Background()
	authority := openAuditTestStore(t)
	request := chainTestIntent(t, 0)
	if _, err := authority.writeIntent(ctx, request, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_business(id) VALUES('scoped-checkpoints')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	chain, err := authority.ChainRange(ctx, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"checkpoint-a", "checkpoint-b"} {
		current, err := NewPlanRepository(authority).CurrentRevision(ctx)
		if err != nil {
			t.Fatal(err)
		}
		checkpoint := generated.AuditCheckpoint{Schema: generated.SchemaIDAuditCheckpoint, SchemaVersion: "1.1.0", CheckpointID: id, FirstEventID: 1, LastEventID: 1, ChainDigest: string(chain.RangeDigest), InstanceID: chain.Links[0].InstanceID, FirstSegmentSequence: 1, LastSegmentSequence: 1, SignerReferenceID: "signer-a", SignerMaterialVersion: "version-a", Status: "pending", ReasonCode: "awaiting-signature", SourceKind: "local", ProofClass: "fixture", VerificationStatus: "pending", RecoveryEpoch: 0}
		if _, err := authority.CreatePendingCheckpoint(ctx, CheckpointCreateRequest{Checkpoint: checkpoint, ExactPath: "audit-anchor/" + id + ".json.enc", Expected: current, KeyDigest: digestForText("key-" + id), RequestDigest: digestForText("request-" + id), Attribution: request.Event.Attribution}); err != nil {
			t.Fatal(err)
		}
	}
	seedReadGrant(t, authority, "checkpoint-reader", "audit.checkpoint.read", "audit-checkpoint", "checkpoint-b", 3, "active")
	scope, err := NewReadAuthorizer(authority).AuthorizeRead(ctx, identity.Principal{ID: "checkpoint-reader", Method: identity.LocalOSPeerMethod}, authorization.ReadTarget{Capability: "audit.checkpoint.read", ResourceKind: "audit-checkpoint"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := authority.health.Revision
	items, err := authority.ListAuditCheckpointsPageScoped(ctx, scope, snapshot, "", 10)
	if err != nil || len(items) != 1 || items[0].CheckpointID != "checkpoint-b" {
		t.Fatalf("items=%#v err=%v", items, err)
	}
	if _, err := authority.conn.ExecContext(ctx, `UPDATE read_grants SET status='revoked' WHERE principal_id='checkpoint-reader'`); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.ListAuditCheckpointsPageScoped(ctx, scope, snapshot, "", 10); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("revoked scope err=%v", err)
	}
}
