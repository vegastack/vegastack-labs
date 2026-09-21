package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// RecoveryDraftSource selects one immutable #124 import draft by its sealed ID.
type RecoveryDraftSource interface {
	GetImportDraftByID(context.Context, string) (store.CredentialImportDraft, error)
}

// RecoveryRevisionSource reads the authoritative local revision/epoch. It is a
// freshness check, not independent custody or former-controller fence proof.
type RecoveryRevisionSource interface {
	CurrentRevision(context.Context) (store.RevisionToken, error)
}

// RecoveryCustodyRequest is the exact metadata a qualified independent source
// must verify. #144 owns the production source, including a native decrypt and
// comparison of the already-existing draft under the replacement host key.
type RecoveryCustodyRequest struct {
	Draft              store.CredentialImportDraft
	PlanID, PlanDigest string
	RunID, StepID      string
	LeaseID            string
	PriorRecoveryEpoch int64
	RecoveryEpoch      int64
}

// RecoveryCustodyProof contains only digest/identity metadata. A caller-built
// value cannot establish independent custody or fencing; only #144's reviewed
// production source may be composed into the server.
type RecoveryCustodyProof struct {
	DraftID, CiphertextName, CiphertextFingerprint  string
	ReferenceID, TargetID, MaterialVersion          string
	PriorRecoveryEpoch, RecoveryEpoch               int64
	CustodyProofDigest, FormerControllerFenceDigest string
	ReplacementHostKeyDigest, SourceEvidenceDigest  string
}

type RecoveryCustodySource interface {
	VerifyRecovery(context.Context, RecoveryCustodyRequest) (RecoveryCustodyProof, error)
}

// RecoveryCustodyVerifier is an internal contract verifier. It is deliberately
// not registered in production composition while no independent source exists.
type RecoveryCustodyVerifier struct {
	drafts   RecoveryDraftSource
	revision RecoveryRevisionSource
	source   RecoveryCustodySource
}

var _ run.CredentialRecoveryVerifier = (*RecoveryCustodyVerifier)(nil)

func NewRecoveryCustodyVerifier(drafts RecoveryDraftSource, revision RecoveryRevisionSource, source RecoveryCustodySource) (*RecoveryCustodyVerifier, error) {
	if drafts == nil || revision == nil || source == nil {
		return nil, recoveryError(generated.ErrorCodePrerequisiteBlocked, "credential-recovery-source-unavailable")
	}
	return &RecoveryCustodyVerifier{drafts: drafts, revision: revision, source: source}, nil
}

func recoveryError(code string, target string) error {
	return failure.New(code, target, false)
}

func (verifier *RecoveryCustodyVerifier) Verify(ctx context.Context, binding run.ExactStepBinding, lifecycle credentialref.LifecycleBinding) (result credentialref.RecoveryVerification, err error) {
	defer func() {
		if recover() != nil {
			result = credentialref.RecoveryVerification{}
			err = recoveryError(generated.ErrorCodeRecoveryRequired, "credential-recovery-verify-uncertain")
		}
	}()
	if verifier == nil || verifier.drafts == nil || verifier.revision == nil || verifier.source == nil || ctx == nil {
		return result, recoveryError(generated.ErrorCodeRecoveryRequired, "credential-recovery-source-unavailable")
	}
	if !credentialref.ValidLifecycleBinding(lifecycle) || lifecycle.Action != credentialref.ActionRecover || lifecycle.DraftID == nil || lifecycle.PriorRecoveryEpoch == nil || lifecycle.CustodyProofDigest == nil || lifecycle.FormerControllerFenceDigest == nil {
		return result, recoveryError(generated.ErrorCodeRecoveryRequired, "credential-recovery-binding")
	}
	if binding.Plan.Binding.RecoveryEpoch != lifecycle.RecoveryEpoch || binding.Run.RecoveryEpoch != lifecycle.RecoveryEpoch || binding.Lease.RecoveryEpoch != lifecycle.RecoveryEpoch || binding.Plan.Binding.StateRevision != lifecycle.StateRevision || binding.Step.OperationID != lifecycle.OperationID || binding.Step.OperationType != string(lifecycle.Action) || binding.Step.TargetID != lifecycle.TargetID || binding.Step.ArtifactDigest != lifecycle.CiphertextFingerprint {
		return result, recoveryError(generated.ErrorCodeRecoveryEpochMismatch, "credential-recovery-step-epoch")
	}
	current, currentErr := verifier.revision.CurrentRevision(ctx)
	if currentErr != nil {
		return result, recoveryError(generated.ErrorCodeRecoveryRequired, "credential-recovery-current-revision")
	}
	if current.RecoveryEpoch != lifecycle.RecoveryEpoch {
		return result, recoveryError(generated.ErrorCodeRecoveryEpochMismatch, "credential-recovery-current-epoch")
	}
	if current.StateRevision != lifecycle.StateRevision {
		return result, recoveryError(generated.ErrorCodePrerequisiteBlocked, "credential-recovery-current-revision")
	}
	draft, draftErr := verifier.drafts.GetImportDraftByID(ctx, *lifecycle.DraftID)
	if draftErr != nil {
		return result, recoveryError(generated.ErrorCodeRecoveryRequired, "credential-recovery-draft-unavailable")
	}
	if draft.RecoveryEpoch <= *lifecycle.PriorRecoveryEpoch {
		return result, recoveryError(generated.ErrorCodeRecoveryEpochMismatch, "credential-recovery-draft-epoch")
	}
	if !draft.MatchesLifecycleBinding(lifecycle) || draft.CiphertextName == "" {
		return result, recoveryError(generated.ErrorCodeRecoveryRequired, "credential-recovery-draft-mismatch")
	}
	request := RecoveryCustodyRequest{Draft: draft, PlanID: binding.Plan.PlanID, PlanDigest: binding.Plan.PlanDigest,
		RunID: binding.Run.RunID, StepID: binding.Step.StepID, LeaseID: binding.Lease.LeaseID,
		PriorRecoveryEpoch: *lifecycle.PriorRecoveryEpoch, RecoveryEpoch: lifecycle.RecoveryEpoch}
	proof, proofErr := verifier.source.VerifyRecovery(ctx, request)
	if proofErr != nil || ctx.Err() != nil {
		return result, recoveryError(generated.ErrorCodeRecoveryRequired, "credential-recovery-independent-proof")
	}
	if proof.DraftID != draft.DraftID || proof.CiphertextName != draft.CiphertextName || proof.CiphertextFingerprint != draft.CiphertextFingerprint || proof.ReferenceID != draft.ReferenceID || proof.TargetID != draft.TargetID || proof.MaterialVersion != draft.MaterialVersion || proof.PriorRecoveryEpoch != *lifecycle.PriorRecoveryEpoch || proof.RecoveryEpoch != lifecycle.RecoveryEpoch || proof.CustodyProofDigest != *lifecycle.CustodyProofDigest || proof.FormerControllerFenceDigest != *lifecycle.FormerControllerFenceDigest || !credentialref.ValidSHA256Digest(proof.ReplacementHostKeyDigest) || !credentialref.ValidSHA256Digest(proof.SourceEvidenceDigest) {
		return result, recoveryError(generated.ErrorCodeRecoveryRequired, "credential-recovery-independent-proof")
	}
	evidenceDigest := recoveryProofDigest(request, proof)
	return credentialref.NewRecoveryVerification(lifecycle, proof.CustodyProofDigest, proof.FormerControllerFenceDigest, evidenceDigest)
}

func recoveryProofDigest(request RecoveryCustodyRequest, proof RecoveryCustodyProof) string {
	hash := sha256.New()
	for _, part := range []string{"credential-recovery-proof-v1", request.PlanID, request.PlanDigest, request.RunID, request.StepID, request.LeaseID,
		proof.DraftID, proof.CiphertextName, proof.CiphertextFingerprint, proof.ReferenceID, proof.TargetID, proof.MaterialVersion,
		strconv.FormatInt(proof.PriorRecoveryEpoch, 10), strconv.FormatInt(proof.RecoveryEpoch, 10), proof.CustodyProofDigest,
		proof.FormerControllerFenceDigest, proof.ReplacementHostKeyDigest, proof.SourceEvidenceDigest} {
		_, _ = hash.Write([]byte(part))
		_, _ = hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}
