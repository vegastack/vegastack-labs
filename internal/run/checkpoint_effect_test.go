package run

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type memoryCheckpointRepository struct {
	checkpoint    generated.AuditCheckpoint
	chain         audit.ChainRange
	path          string
	payload       []byte
	payloadDigest audit.Fingerprint
}

func (repo *memoryCheckpointRepository) GetAuditCheckpoint(context.Context, string) (generated.AuditCheckpoint, error) {
	return repo.checkpoint, nil
}
func (repo *memoryCheckpointRepository) ChainRange(context.Context, audit.EventID, audit.EventID) (audit.ChainRange, error) {
	return repo.chain, nil
}
func (repo *memoryCheckpointRepository) RecordCheckpointSignature(_ context.Context, request store.CheckpointSignatureRequest) (generated.AuditCheckpoint, error) {
	value, key := string(request.SignatureDigest), request.PublicKeyID
	repo.checkpoint.SignatureDigest, repo.checkpoint.PublicKeyID, repo.checkpoint.Status = &value, &key, "signed"
	repo.path, repo.payload, repo.payloadDigest = request.ExactPath, request.EncryptedPayload, request.PayloadDigest
	return repo.checkpoint, nil
}
func (repo *memoryCheckpointRepository) RecordCheckpointExport(_ context.Context, request store.CheckpointExportRequest) (generated.AuditCheckpoint, error) {
	value := string(request.ReceiptDigest)
	repo.checkpoint.ExportReceiptDigest, repo.checkpoint.Status = &value, "export-pending"
	return repo.checkpoint, nil
}
func (repo *memoryCheckpointRepository) SettleCheckpoint(_ context.Context, request store.CheckpointSettleRequest) (generated.AuditCheckpoint, error) {
	value := string(request.IndependentDigest)
	repo.checkpoint.IndependentReadDigest, repo.checkpoint.Status = &value, "anchored"
	return repo.checkpoint, nil
}
func (repo *memoryCheckpointRepository) CheckpointExportPayload(context.Context, string) (string, []byte, audit.Fingerprint, error) {
	return repo.path, repo.payload, repo.payloadDigest, nil
}

type checkpointTestSigner struct {
	private ed25519.PrivateKey
	last    audit.Signature
}

func (signer *checkpointTestSigner) Sign(_ context.Context, digest audit.Fingerprint, _ credentialref.Reference) (audit.Signature, error) {
	bytes := ed25519.Sign(signer.private, []byte(digest))
	signer.last = audit.Signature{PublicKeyID: "key-a", Bytes: bytes, Digest: audit.SignatureDigest(bytes)}
	return signer.last, nil
}
func (*checkpointTestSigner) Verify(digest audit.Fingerprint, signature audit.Signature, key audit.PublicKey) error {
	if key.ID != signature.PublicKeyID || !ed25519.Verify(ed25519.PublicKey(key.Bytes), []byte(digest), signature.Bytes) {
		return errors.New("bad signature")
	}
	return nil
}

type passthroughEncryptor struct{}

func (passthroughEncryptor) Seal(_ context.Context, value []byte) ([]byte, error) {
	return append([]byte("encrypted:"), value...), nil
}

type uncertainCheckpointStore struct {
	signer  *checkpointTestSigner
	repo    *memoryCheckpointRepository
	writes  int
	fail    bool
	receipt audit.Fingerprint
}

func (store *uncertainCheckpointStore) PutIfAbsent(_ context.Context, path string, payload []byte, digest audit.Fingerprint) (audit.ExportReceipt, error) {
	store.writes++
	store.receipt = checkpointDigest([]byte("receipt"))
	if store.fail {
		store.fail = false
		return audit.ExportReceipt{}, errors.New("timeout after write")
	}
	return audit.ExportReceipt{CheckpointID: store.repo.checkpoint.CheckpointID, ExactPath: path, PayloadDigest: digest, ReceiptDigest: store.receipt}, nil
}
func (store *uncertainCheckpointStore) ReadLast(_ context.Context, namespace string) (audit.IndependentCheckpoint, error) {
	cp := store.repo.checkpoint
	reference := credentialref.Reference{ID: cp.SignerReferenceID, Consumer: "core.audit.signer"}
	signed, err := audit.CheckpointBindingDigest(audit.EventID(cp.FirstEventID), audit.EventID(cp.LastEventID), cp.FirstSegmentSequence, cp.LastSegmentSequence, audit.Fingerprint(cp.ChainDigest), cp.InstanceID, cp.RecoveryEpoch, reference, cp.SignerMaterialVersion, namespace)
	if err != nil {
		return audit.IndependentCheckpoint{}, err
	}
	return audit.IndependentCheckpoint{CheckpointID: cp.CheckpointID, InstanceID: cp.InstanceID, RecoveryEpoch: cp.RecoveryEpoch, LastEventID: audit.EventID(cp.LastEventID), LastSequence: cp.LastSegmentSequence, ChainDigest: audit.Fingerprint(cp.ChainDigest), SignerReference: reference, MaterialVersion: cp.SignerMaterialVersion, Namespace: namespace, SignedDigest: signed, Signature: store.signer.last, ExportReceipt: store.receipt, IndependentRead: checkpointDigest([]byte("independent"))}, nil
}

func TestExportTimeoutNeverMarksCheckpointAnchored(t *testing.T) {
	digest := audit.Fingerprint("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	link := audit.ChainLink{EventID: 1, InstanceID: "instance-a", RecoveryEpoch: 0, SegmentSequence: 1, LinkDigest: digest}
	repo := &memoryCheckpointRepository{chain: audit.ChainRange{FirstEventID: 1, LastEventID: 1, Links: []audit.ChainLink{link}, RangeDigest: digest}, checkpoint: generated.AuditCheckpoint{CheckpointID: "checkpoint-a", InstanceID: "instance-a", RecoveryEpoch: 0, FirstEventID: 1, LastEventID: 1, FirstSegmentSequence: 1, LastSegmentSequence: 1, ChainDigest: string(digest), SignerReferenceID: "signer-a", SignerMaterialVersion: "version-a", Status: "pending"}}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := &checkpointTestSigner{private: private}
	external := &uncertainCheckpointStore{signer: signer, repo: repo, fail: true}
	effect, err := NewCheckpointEffect(repo, signer, external, external, passthroughEncryptor{}, credentialref.Reference{ID: "signer-a", Consumer: "core.audit.signer"}, audit.PublicKey{ID: "key-a", Bytes: private.Public().(ed25519.PublicKey)}, "audit-anchor", func() time.Time { return time.Date(2026, 9, 16, 8, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	binding := ExactStepBinding{Plan: generated.Plan{PlanID: "plan-a", PlanDigest: string(digest), ExecutorMode: "central"}, Run: generated.Run{RunID: "run-a", PlanID: "plan-a", PlanDigest: string(digest), ExecutorMode: "central", RecoveryEpoch: 0}, Step: generated.RunStep{StepID: "step-a", OperationID: "checkpoint-a", OperationType: "audit.checkpoint.anchor", AdapterID: "core.audit", TargetID: "instance-a", InputDigest: string(digest), ArtifactDigest: string(digest), EffectState: "intent-recorded"}, Lease: generated.ExecutorLease{Status: "active", PlanID: "plan-a", PlanDigest: string(digest), RunID: "run-a", StepID: "step-a", ArtifactDigest: string(digest), RecoveryEpoch: 0}}
	if result, err := effect.Execute(context.Background(), binding); err == nil || result.Status != "partial" || repo.checkpoint.Status == "anchored" {
		t.Fatal("uncertain export falsely settled")
	}
	result, err := effect.Execute(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "succeeded" || repo.checkpoint.Status != "anchored" || external.writes != 2 {
		t.Fatal("idempotent settlement failed")
	}
}

var _ adapter.CheckpointExporter = (*uncertainCheckpointStore)(nil)
var _ adapter.CheckpointReader = (*uncertainCheckpointStore)(nil)
