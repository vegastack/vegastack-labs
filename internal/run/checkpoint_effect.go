package run

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type CheckpointRepository interface {
	GetAuditCheckpoint(context.Context, string) (generated.AuditCheckpoint, error)
	ChainRange(context.Context, audit.EventID, audit.EventID) (audit.ChainRange, error)
	RecordCheckpointSignature(context.Context, store.CheckpointSignatureRequest) (generated.AuditCheckpoint, error)
	RecordCheckpointExport(context.Context, store.CheckpointExportRequest) (generated.AuditCheckpoint, error)
	SettleCheckpoint(context.Context, store.CheckpointSettleRequest) (generated.AuditCheckpoint, error)
	CheckpointExportPayload(context.Context, string) (string, []byte, audit.Fingerprint, error)
}

type CheckpointEncryptor interface {
	Seal(context.Context, []byte) ([]byte, error)
}

type CheckpointEffect struct {
	repository CheckpointRepository
	signer     audit.CheckpointSigner
	exporter   adapter.CheckpointExporter
	reader     adapter.CheckpointReader
	encryptor  CheckpointEncryptor
	reference  credentialref.Reference
	publicKey  audit.PublicKey
	namespace  string
	clock      func() time.Time
}

func NewCheckpointEffect(repository CheckpointRepository, signer audit.CheckpointSigner, exporter adapter.CheckpointExporter, reader adapter.CheckpointReader, encryptor CheckpointEncryptor, reference credentialref.Reference, publicKey audit.PublicKey, namespace string, clock func() time.Time) (*CheckpointEffect, error) {
	if repository == nil || signer == nil || exporter == nil || reader == nil || encryptor == nil || reference.ID == "" || reference.Consumer != "core.audit.signer" || publicKey.ID == "" || len(publicKey.Bytes) == 0 || namespace == "" {
		return nil, runError(generated.ErrorCodePrerequisiteBlocked, "audit-checkpoint-effect")
	}
	if clock == nil {
		clock = time.Now
	}
	return &CheckpointEffect{repository: repository, signer: signer, exporter: exporter, reader: reader, encryptor: encryptor, reference: reference, publicKey: publicKey, namespace: namespace, clock: clock}, nil
}

func (effect *CheckpointEffect) Execute(ctx context.Context, binding ExactStepBinding) (adapter.Effect, error) {
	if effect == nil || binding.Plan.ExecutorMode != "central" || binding.Run.ExecutorMode != "central" || binding.Step.AdapterID != "core.audit" || binding.Step.OperationType != "audit.checkpoint.anchor" || binding.Step.InputDigest != binding.Step.ArtifactDigest || binding.Step.EffectState != "intent-recorded" || binding.Lease.Status != "active" || binding.Lease.PlanID != binding.Plan.PlanID || binding.Lease.PlanDigest != binding.Plan.PlanDigest || binding.Lease.RunID != binding.Run.RunID || binding.Lease.StepID != binding.Step.StepID || binding.Lease.ArtifactDigest != binding.Step.ArtifactDigest || binding.Lease.RecoveryEpoch != binding.Run.RecoveryEpoch {
		return adapter.Effect{}, runError(generated.ErrorCodePrerequisiteBlocked, "audit-checkpoint-binding")
	}
	cp, err := effect.repository.GetAuditCheckpoint(ctx, binding.Step.OperationID)
	if err != nil {
		return adapter.Effect{}, err
	}
	if cp.ChainDigest != binding.Step.ArtifactDigest || cp.InstanceID != binding.Step.TargetID || cp.RecoveryEpoch != binding.Run.RecoveryEpoch || cp.SignerReferenceID != effect.reference.ID {
		return adapter.Effect{}, runError(generated.ErrorCodePlanStale, "audit-checkpoint")
	}
	chain, err := effect.repository.ChainRange(ctx, audit.EventID(cp.FirstEventID), audit.EventID(cp.LastEventID))
	if err != nil || string(chain.RangeDigest) != cp.ChainDigest {
		return adapter.Effect{}, firstError(err, runError(generated.ErrorCodeIntegrityFailure, "audit-checkpoint-range"))
	}
	digest, err := audit.CheckpointDigest(chain, cp.InstanceID, cp.RecoveryEpoch, effect.reference, cp.SignerMaterialVersion, effect.namespace)
	if err != nil {
		return adapter.Effect{}, err
	}
	if cp.Status == "pending" {
		signature, err := effect.signer.Sign(ctx, digest, effect.reference)
		if err != nil {
			return adapter.Effect{}, err
		}
		if signature.PublicKeyID != effect.publicKey.ID || signature.Digest != audit.SignatureDigest(signature.Bytes) || effect.signer.Verify(digest, signature, effect.publicKey) != nil {
			return adapter.Effect{}, runError(generated.ErrorCodeIntegrityFailure, "audit-checkpoint-signature")
		}
		signed := audit.IndependentCheckpoint{CheckpointID: cp.CheckpointID, InstanceID: cp.InstanceID, RecoveryEpoch: cp.RecoveryEpoch, LastEventID: audit.EventID(cp.LastEventID), LastSequence: cp.LastSegmentSequence, ChainDigest: chain.RangeDigest, Signature: signature}
		signed.SignerReference, signed.MaterialVersion, signed.Namespace, signed.SignedDigest = effect.reference, cp.SignerMaterialVersion, effect.namespace, digest
		plaintext, err := audit.EncodeSignedCheckpoint(signed)
		if err != nil {
			return adapter.Effect{}, err
		}
		encrypted, err := effect.encryptor.Seal(ctx, plaintext)
		if err != nil {
			return adapter.Effect{}, err
		}
		payloadDigest := checkpointDigest(encrypted)
		cp, err = effect.repository.RecordCheckpointSignature(ctx, store.CheckpointSignatureRequest{CheckpointID: cp.CheckpointID, PublicKeyID: signature.PublicKeyID, ExactPath: effect.namespace + "/" + cp.CheckpointID + ".json.enc", SignatureDigest: signature.Digest, PayloadDigest: payloadDigest, EncryptedPayload: encrypted, At: effect.clock().UTC(), KeyDigest: checkpointDigest([]byte(binding.Run.RunID + ":signed")), RequestDigest: checkpointDigest([]byte(string(signature.Digest) + string(payloadDigest))), Attribution: binding.Attribution})
		if err != nil {
			return adapter.Effect{}, err
		}
	}
	if cp.Status == "signed" {
		path, payload, payloadDigest, err := effect.repository.CheckpointExportPayload(ctx, cp.CheckpointID)
		if err != nil {
			return adapter.Effect{}, err
		}
		receipt, err := effect.exporter.PutIfAbsent(ctx, path, payload, payloadDigest)
		if err != nil {
			return adapter.Effect{Status: "partial", ResultDigest: cp.ChainDigest, Changed: true, EffectObserved: true}, err
		}
		if receipt.CheckpointID != cp.CheckpointID || receipt.ExactPath != path || receipt.PayloadDigest != payloadDigest || !audit.ValidFingerprint(receipt.ReceiptDigest) {
			return adapter.Effect{}, runError(generated.ErrorCodeIntegrityFailure, "audit-checkpoint-receipt")
		}
		cp, err = effect.repository.RecordCheckpointExport(ctx, store.CheckpointExportRequest{CheckpointID: cp.CheckpointID, ReceiptDigest: receipt.ReceiptDigest, At: effect.clock().UTC(), KeyDigest: checkpointDigest([]byte(binding.Run.RunID + ":exported")), RequestDigest: checkpointDigest([]byte(string(receipt.ReceiptDigest))), Attribution: binding.Attribution})
		if err != nil {
			return adapter.Effect{}, err
		}
	}
	if cp.Status == "export-pending" {
		remote, err := effect.reader.ReadLast(ctx, effect.namespace)
		if err != nil {
			return adapter.Effect{Status: "partial", ResultDigest: cp.ChainDigest, Changed: true, EffectObserved: true}, err
		}
		if remote.CheckpointID != cp.CheckpointID || remote.InstanceID != cp.InstanceID || remote.RecoveryEpoch != cp.RecoveryEpoch || int64(remote.LastEventID) != cp.LastEventID || remote.LastSequence != cp.LastSegmentSequence || string(remote.ChainDigest) != cp.ChainDigest || remote.SignerReference != effect.reference || remote.MaterialVersion != cp.SignerMaterialVersion || remote.Namespace != effect.namespace || remote.SignedDigest != digest || cp.ExportReceiptDigest == nil || remote.ExportReceipt != audit.Fingerprint(*cp.ExportReceiptDigest) || effect.signer.Verify(digest, remote.Signature, effect.publicKey) != nil || !audit.ValidFingerprint(remote.IndependentRead) {
			return adapter.Effect{}, runError(generated.ErrorCodeIntegrityFailure, "audit-checkpoint-independent")
		}
		cp, err = effect.repository.SettleCheckpoint(ctx, store.CheckpointSettleRequest{CheckpointID: cp.CheckpointID, IndependentDigest: remote.IndependentRead, At: effect.clock().UTC(), KeyDigest: checkpointDigest([]byte(binding.Run.RunID + ":anchored")), RequestDigest: checkpointDigest([]byte(string(remote.IndependentRead))), Attribution: binding.Attribution})
		if err != nil {
			return adapter.Effect{}, err
		}
	}
	if cp.Status != "anchored" {
		return adapter.Effect{}, errors.New("audit checkpoint did not settle")
	}
	return adapter.Effect{Status: "succeeded", ResultDigest: cp.ChainDigest, Changed: true, EffectObserved: true}, nil
}

func (effect *CheckpointEffect) Verify(ctx context.Context, binding ExactStepBinding, result adapter.Effect) (adapter.Verification, error) {
	if adapter.ValidateEffect(result) != nil || result.Status != "succeeded" {
		return adapter.Verification{}, runError(generated.ErrorCodeIntegrityFailure, "audit-checkpoint-effect")
	}
	cp, err := effect.repository.GetAuditCheckpoint(ctx, binding.Step.OperationID)
	if err != nil {
		return adapter.Verification{}, err
	}
	verified := cp.Status == "anchored" && cp.ChainDigest == result.ResultDigest && cp.IndependentReadDigest != nil && cp.ExportReceiptDigest != nil && cp.SignatureDigest != nil
	return adapter.Verification{Verified: verified, Digest: result.ResultDigest}, nil
}

func checkpointDigest(data []byte) audit.Fingerprint {
	sum := sha256.Sum256(data)
	return audit.Fingerprint("sha256:" + hex.EncodeToString(sum[:]))
}

type CoreRouter struct{ Gate, Checkpoint, Recovery, Schedule, ScheduleObserve CoreEffect }

func (router CoreRouter) Execute(ctx context.Context, binding ExactStepBinding) (adapter.Effect, error) {
	if binding.Step.AdapterID == "core.gate" && router.Gate != nil {
		return router.Gate.Execute(ctx, binding)
	}
	if binding.Step.AdapterID == "core.audit" && router.Checkpoint != nil {
		return router.Checkpoint.Execute(ctx, binding)
	}
	if binding.Step.AdapterID == "core.recovery" && router.Recovery != nil {
		return router.Recovery.Execute(ctx, binding)
	}
	if binding.Step.AdapterID == "core.schedule" && router.Schedule != nil {
		return router.Schedule.Execute(ctx, binding)
	}
	if binding.Step.AdapterID == "core.schedule-observe" && router.ScheduleObserve != nil {
		return router.ScheduleObserve.Execute(ctx, binding)
	}
	return adapter.Effect{}, runError(generated.ErrorCodePrerequisiteBlocked, "core-effect")
}

func (router CoreRouter) Verify(ctx context.Context, binding ExactStepBinding, result adapter.Effect) (adapter.Verification, error) {
	if binding.Step.AdapterID == "core.gate" && router.Gate != nil {
		return router.Gate.Verify(ctx, binding, result)
	}
	if binding.Step.AdapterID == "core.audit" && router.Checkpoint != nil {
		return router.Checkpoint.Verify(ctx, binding, result)
	}
	if binding.Step.AdapterID == "core.recovery" && router.Recovery != nil {
		return router.Recovery.Verify(ctx, binding, result)
	}
	if binding.Step.AdapterID == "core.schedule" && router.Schedule != nil {
		return router.Schedule.Verify(ctx, binding, result)
	}
	if binding.Step.AdapterID == "core.schedule-observe" && router.ScheduleObserve != nil {
		return router.ScheduleObserve.Verify(ctx, binding, result)
	}
	return adapter.Verification{}, runError(generated.ErrorCodePrerequisiteBlocked, "core-effect")
}
