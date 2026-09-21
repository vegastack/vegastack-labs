package run

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// CredentialLifecycleRepository is the exact, metadata-only store surface the
// core credential effect requires. It never exposes credential material.
type CredentialLifecycleRepository interface {
	GetLifecycleBinding(context.Context, generated.Plan, string) (credentialref.LifecycleBinding, error)
	GetReference(context.Context, string) (generated.CredentialReference, error)
	GetCredentialVersion(context.Context, string, string) (generated.CredentialReference, error)
	GetImportDraftByID(context.Context, string) (store.CredentialImportDraft, error)
	ApplyCredentialLifecycle(context.Context, store.CredentialLifecycleApplyRequest) (generated.CredentialReference, error)
}

// CredentialLifecycleVerifier proves every declared positive and required-denied
// consumer against real cold-start/restart observation, resolving credential
// material only inside itself and never returning it.
type CredentialLifecycleVerifier interface {
	Verify(context.Context, ExactStepBinding, credentialref.LifecycleBinding) ([]credentialref.ConsumerVerification, error)
}

// CredentialRecoveryVerifier proves independent custody and former-controller
// fence evidence for a clean-host recovery bound to the current external epoch.
type CredentialRecoveryVerifier interface {
	Verify(context.Context, ExactStepBinding, credentialref.LifecycleBinding) (credentialref.RecoveryVerification, error)
}

// UnavailableCredentialLifecycleVerifier is the fail-closed default: with no
// production consumer verifier registered, an activation or rotation cannot
// become ready from a caller assertion or a fixture.
type UnavailableCredentialLifecycleVerifier struct{}

func (UnavailableCredentialLifecycleVerifier) Verify(context.Context, ExactStepBinding, credentialref.LifecycleBinding) ([]credentialref.ConsumerVerification, error) {
	return nil, runError(generated.ErrorCodePrerequisiteBlocked, "credential-consumer-verifier-unavailable")
}

// UnavailableCredentialRecoveryVerifier is the fail-closed default for
// clean-host recovery custody and fence proof.
type UnavailableCredentialRecoveryVerifier struct{}

func (UnavailableCredentialRecoveryVerifier) Verify(context.Context, ExactStepBinding, credentialref.LifecycleBinding) (credentialref.RecoveryVerification, error) {
	return credentialref.RecoveryVerification{}, runError(generated.ErrorCodePrerequisiteBlocked, "credential-recovery-verifier-unavailable")
}

// CoreCredentialEffect executes exactly one human-authorized credential
// lifecycle action on the control plane. It resolves credential material only
// after admission, lease and durable intent, only inside the consumer verifier,
// and never persists or returns it.
type CoreCredentialEffect struct {
	repository        CredentialLifecycleRepository
	approvals         GateApprovalSource
	gate              GateVerifier
	lifecycleVerifier CredentialLifecycleVerifier
	recoveryVerifier  CredentialRecoveryVerifier
	clock             func() time.Time
}

func NewCoreCredentialEffect(repository CredentialLifecycleRepository, approvals GateApprovalSource, gate GateVerifier, lifecycleVerifier CredentialLifecycleVerifier, recoveryVerifier CredentialRecoveryVerifier, clock func() time.Time) (*CoreCredentialEffect, error) {
	if repository == nil || approvals == nil || gate == nil || lifecycleVerifier == nil || recoveryVerifier == nil {
		return nil, runError(generated.ErrorCodeInputInvalid, "credential-effect")
	}
	if clock == nil {
		clock = time.Now
	}
	return &CoreCredentialEffect{repository: repository, approvals: approvals, gate: gate, lifecycleVerifier: lifecycleVerifier, recoveryVerifier: recoveryVerifier, clock: clock}, nil
}

func coreCredentialDigest(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte(part))
		hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func (effect *CoreCredentialEffect) Execute(ctx context.Context, binding ExactStepBinding) (adapter.Effect, error) {
	if effect == nil || effect.repository == nil || effect.approvals == nil {
		return adapter.Effect{}, runError(generated.ErrorCodePrerequisiteBlocked, "credential-effect")
	}
	if binding.Plan.ExecutorMode != "central" || binding.Run.ExecutorMode != "central" || binding.Step.AdapterID != "core.credential" || !isCredentialLifecycleOperation(binding.Step.OperationType) || binding.Step.InputDigest != binding.Step.ArtifactDigest || binding.Step.EffectState != "intent-recorded" || binding.Lease.Status != "active" || binding.Lease.StepID != binding.Step.StepID || binding.Lease.RunID != binding.Run.RunID || binding.Lease.PlanID != binding.Plan.PlanID || binding.Lease.PlanDigest != binding.Plan.PlanDigest || binding.Lease.ArtifactDigest != binding.Step.ArtifactDigest || binding.Plan.Binding.StateRevision != binding.Run.StateRevision || binding.Plan.Binding.RecoveryEpoch != binding.Run.RecoveryEpoch || binding.Plan.Binding.RecoveryEpoch != binding.Lease.RecoveryEpoch {
		return adapter.Effect{}, runError(generated.ErrorCodePrerequisiteBlocked, "credential-exact-binding")
	}
	if binding.Plan.AuthorizationBranch != "human" || binding.Run.AcknowledgementID == nil {
		return adapter.Effect{}, runError(generated.ErrorCodeApprovalRequired, "credential-human")
	}
	approval, err := effect.approvals.Get(ctx, binding.Plan.PlanID)
	if err != nil {
		return adapter.Effect{}, err
	}
	if !approval.Consumed || approval.Acknowledgement.Status != "approved" || approval.Acknowledgement.AcknowledgementID != *binding.Run.AcknowledgementID || approval.Acknowledgement.PlanDigest != binding.Plan.PlanDigest || approval.Acknowledgement.HumanID == "" {
		return adapter.Effect{}, runError(generated.ErrorCodeApprovalRequired, "credential-human")
	}

	lifecycleBinding, err := effect.repository.GetLifecycleBinding(ctx, binding.Plan, binding.Step.OperationID)
	if err != nil {
		return adapter.Effect{}, err
	}
	if lifecycleBinding.OperationID != binding.Step.OperationID || lifecycleBinding.TargetID != binding.Step.TargetID || string(lifecycleBinding.Action) != binding.Step.OperationType || lifecycleBinding.CiphertextFingerprint != binding.Step.ArtifactDigest || lifecycleBinding.RecoveryEpoch != binding.Plan.Binding.RecoveryEpoch {
		return adapter.Effect{}, runError(generated.ErrorCodeIntegrityFailure, "credential-lifecycle-binding")
	}

	plannedOperation := exactPlanOperation(binding.Plan, binding.Step.OperationID)
	if plannedOperation == nil {
		return adapter.Effect{}, runError(generated.ErrorCodeIntegrityFailure, "credential-lifecycle-operation")
	}

	attribution := binding.Attribution
	humanID := approval.Acknowledgement.HumanID
	attribution.ResponsibleHumanPrincipalID = &humanID

	consumerID, purposeID, err := effect.referenceIdentity(ctx, lifecycleBinding)
	if err != nil {
		return adapter.Effect{}, err
	}

	expectedStateRevision := binding.Plan.Binding.StateRevision
	reference := generated.CredentialReference{
		Schema: generated.SchemaIDCredentialReference, SchemaVersion: "1.1.0",
		ReferenceID: lifecycleBinding.ReferenceID, ConsumerID: consumerID, PurposeID: purposeID,
		TargetID: lifecycleBinding.TargetID, ResolverID: lifecycleBinding.ResolverID,
		MaterialVersion: lifecycleBinding.MaterialVersion, Fingerprint: lifecycleBinding.CiphertextFingerprint,
		StateRevision: expectedStateRevision + 1, RecoveryEpoch: lifecycleBinding.RecoveryEpoch,
		VerifiedConsumerIDs: []string{},
	}

	var verifications []credentialref.ConsumerVerification
	var recovery *credentialref.RecoveryVerification

	switch lifecycleBinding.Action {
	case credentialref.ActionStage:
		reference.Status = "staged"
	case credentialref.ActionActivate, credentialref.ActionRotate:
		if err := effect.gate.VerifySecretStep(ctx, binding.Plan, *plannedOperation); err != nil {
			return adapter.Effect{}, err
		}
		results, verifyErr := guardedLifecycleVerify(ctx, effect.lifecycleVerifier, binding, lifecycleBinding)
		if verifyErr != nil {
			if _, unavailable := effect.lifecycleVerifier.(UnavailableCredentialLifecycleVerifier); unavailable {
				// The built-in sentinel performs no external work.
				return adapter.Effect{}, verifyErr
			}
			// A verifier may have restarted or read a consumer before failing.
			// The engine must persist effect-unknown/partial, never retry it as
			// an unobserved pre-effect failure.
			return adapter.Effect{EffectObserved: true}, verifyErr
		}
		verifications = results
		activatedAt := effect.clock().UTC().Truncate(time.Second).Format(time.RFC3339)
		reference.Status = "active"
		reference.ActivatedAt = &activatedAt
		reference.VerifiedConsumerIDs = sortedConsumers(lifecycleBinding.ConsumerIDs)
	case credentialref.ActionRevoke:
		reference.Status = "revoked"
	case credentialref.ActionRecover:
		if err := effect.gate.VerifySecretStep(ctx, binding.Plan, *plannedOperation); err != nil {
			return adapter.Effect{}, err
		}
		result, verifyErr := guardedRecoveryVerify(ctx, effect.recoveryVerifier, binding, lifecycleBinding)
		if verifyErr != nil {
			if _, unavailable := effect.recoveryVerifier.(UnavailableCredentialRecoveryVerifier); unavailable {
				return adapter.Effect{}, verifyErr
			}
			return adapter.Effect{EffectObserved: true}, verifyErr
		}
		recovery = &result
		reference.Status = "staged"
	default:
		return adapter.Effect{}, runError(generated.ErrorCodePrerequisiteBlocked, "credential-lifecycle-action")
	}

	base := []string{binding.Plan.PlanID, binding.Plan.PlanDigest, binding.Run.RunID, binding.Step.StepID, binding.Lease.LeaseID, binding.Step.OperationType, binding.Step.OperationID, binding.Step.ArtifactDigest}
	stage := store.CredentialStageRequest{
		Reference: reference, DeclarationID: binding.Plan.DeclarationID, DeclarationRevision: binding.Plan.Binding.DeclarationRevision,
		PlanID: binding.Plan.PlanID, PlanDigest: binding.Plan.PlanDigest, RunID: binding.Run.RunID, StepID: binding.Step.StepID,
		LeaseID: binding.Lease.LeaseID, HumanID: humanID,
		Expected:    store.RevisionToken{StateRevision: expectedStateRevision, RecoveryEpoch: lifecycleBinding.RecoveryEpoch},
		Attribution: attribution,
		KeyDigest:   coreCredentialDigest(append(base, "key")...), RequestDigest: coreCredentialDigest(append(base, "request")...),
	}
	applied, err := effect.repository.ApplyCredentialLifecycle(ctx, store.CredentialLifecycleApplyRequest{Binding: lifecycleBinding, Stage: stage, Verifications: verifications, Recovery: recovery})
	if err != nil {
		return adapter.Effect{}, err
	}
	if applied.ReferenceID != lifecycleBinding.ReferenceID || applied.Status != reference.Status || applied.MaterialVersion != lifecycleBinding.MaterialVersion {
		return adapter.Effect{}, runError(generated.ErrorCodeIntegrityFailure, "credential-lifecycle-applied")
	}
	return adapter.Effect{Status: "succeeded", ResultDigest: lifecycleBinding.Digest(), Changed: true, EffectObserved: true}, nil
}

func (effect *CoreCredentialEffect) referenceIdentity(ctx context.Context, binding credentialref.LifecycleBinding) (string, string, error) {
	switch binding.Action {
	case credentialref.ActionStage, credentialref.ActionRecover, credentialref.ActionRotate:
		if binding.DraftID == nil {
			return "", "", runError(generated.ErrorCodeInputInvalid, "credential-import-draft")
		}
		draft, err := effect.repository.GetImportDraftByID(ctx, *binding.DraftID)
		if err != nil {
			return "", "", err
		}
		if !draft.MatchesLifecycleBinding(binding) {
			return "", "", runError(generated.ErrorCodePrerequisiteBlocked, "credential-import-draft")
		}
		return draft.ConsumerID, draft.PurposeID, nil
	default:
		current, err := effect.repository.GetCredentialVersion(ctx, binding.ReferenceID, binding.MaterialVersion)
		if err != nil {
			return "", "", err
		}
		if current.TargetID != binding.TargetID || current.ResolverID != binding.ResolverID {
			return "", "", runError(generated.ErrorCodePrerequisiteBlocked, "credential-reference")
		}
		return current.ConsumerID, current.PurposeID, nil
	}
}

func (effect *CoreCredentialEffect) Verify(ctx context.Context, binding ExactStepBinding, result adapter.Effect) (adapter.Verification, error) {
	if adapter.ValidateEffect(result) != nil || result.Status != "succeeded" {
		return adapter.Verification{}, runError(generated.ErrorCodeIntegrityFailure, "credential-effect")
	}
	lifecycleBinding, err := effect.repository.GetLifecycleBinding(ctx, binding.Plan, binding.Step.OperationID)
	if err != nil {
		return adapter.Verification{}, err
	}
	if lifecycleBinding.Digest() != result.ResultDigest {
		return adapter.Verification{Verified: false, Digest: result.ResultDigest}, errors.New("credential lifecycle digest mismatch")
	}
	version, err := effect.repository.GetCredentialVersion(ctx, lifecycleBinding.ReferenceID, lifecycleBinding.MaterialVersion)
	if err != nil {
		return adapter.Verification{}, err
	}
	wantStatus := map[credentialref.LifecycleAction]string{
		credentialref.ActionStage: "staged", credentialref.ActionActivate: "active",
		credentialref.ActionRotate: "active", credentialref.ActionRevoke: "revoked",
		credentialref.ActionRecover: "staged",
	}[lifecycleBinding.Action]
	if version.MaterialVersion == lifecycleBinding.MaterialVersion && version.Status == wantStatus && version.StateRevision == binding.Run.StateRevision+1 && version.RecoveryEpoch == lifecycleBinding.RecoveryEpoch {
		return adapter.Verification{Verified: true, Digest: result.ResultDigest}, nil
	}
	return adapter.Verification{Verified: false, Digest: result.ResultDigest}, errors.New("credential lifecycle postcondition not observed")
}

func exactPlanOperation(plan generated.Plan, operationID string) *generated.PlanOperation {
	for index := range plan.Operations {
		if plan.Operations[index].OperationID == operationID {
			return &plan.Operations[index]
		}
	}
	return nil
}

func sortedConsumers(values []string) []string {
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	return sorted
}
