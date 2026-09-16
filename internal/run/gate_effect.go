package run

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type GateRepository interface {
	GetGateDraft(context.Context, string) (store.GateDraft, error)
	GetProfileDraft(context.Context, string) (store.ProfileDraft, error)
	GetAppliedProfileScope(context.Context) (store.GateAppliedProfile, error)
	ApplyGateEvidence(context.Context, store.GateApplyRequest) (generated.GateEvidence, error)
	ApplyProfileBinding(context.Context, store.ProfileApplyRequest) (store.GateAppliedProfile, error)
	ListAppliedGateEvidence(context.Context, string, string) ([]generated.GateEvidence, error)
}

type GateApprovalSource interface {
	Get(context.Context, string) (acknowledgement.Stored, error)
}

type CoreGateEffect struct {
	repository                  GateRepository
	approvals                   GateApprovalSource
	releaseBuildID, toolVersion string
	clock                       func() time.Time
}

func NewCoreGateEffect(repository GateRepository, approvals GateApprovalSource, releaseBuildID, toolVersion string, clock func() time.Time) (*CoreGateEffect, error) {
	if repository == nil || approvals == nil || releaseBuildID == "" || toolVersion == "" {
		return nil, runError(generated.ErrorCodeInputInvalid, "gate-effect")
	}
	if clock == nil {
		clock = time.Now
	}
	return &CoreGateEffect{repository: repository, approvals: approvals, releaseBuildID: releaseBuildID, toolVersion: toolVersion, clock: clock}, nil
}

func coreGateDigest(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte(part))
		hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func (effect *CoreGateEffect) Execute(ctx context.Context, binding ExactStepBinding) (adapter.Effect, error) {
	if effect == nil || effect.approvals == nil {
		return adapter.Effect{}, runError(generated.ErrorCodePrerequisiteBlocked, "gate-approval-source")
	}
	if effect == nil || effect.repository == nil || binding.Plan.ExecutorMode != "central" || binding.Run.ExecutorMode != "central" || binding.Step.AdapterID != "core.gate" || !isGateOperation(binding.Step.OperationType) || binding.Step.InputDigest != binding.Step.ArtifactDigest || binding.Step.EffectState != "intent-recorded" || binding.Lease.Status != "active" || binding.Lease.StepID != binding.Step.StepID || binding.Lease.RunID != binding.Run.RunID || binding.Lease.PlanID != binding.Plan.PlanID || binding.Lease.PlanDigest != binding.Plan.PlanDigest || binding.Lease.ArtifactDigest != binding.Step.ArtifactDigest || binding.Plan.Binding.StateRevision != binding.Run.StateRevision || binding.Plan.Binding.RecoveryEpoch != binding.Run.RecoveryEpoch || binding.Plan.Binding.RecoveryEpoch != binding.Lease.RecoveryEpoch {
		return adapter.Effect{}, runError(generated.ErrorCodePrerequisiteBlocked, "gate-exact-binding")
	}
	if binding.Plan.AuthorizationBranch != "human" || binding.Run.AcknowledgementID == nil {
		return adapter.Effect{}, runError(generated.ErrorCodeApprovalRequired, "gate-human")
	}
	approval, err := effect.approvals.Get(ctx, binding.Plan.PlanID)
	if err != nil {
		return adapter.Effect{}, err
	}
	if !approval.Consumed || approval.Acknowledgement.Status != "approved" || approval.Acknowledgement.AcknowledgementID != *binding.Run.AcknowledgementID || approval.Acknowledgement.PlanDigest != binding.Plan.PlanDigest || approval.Acknowledgement.HumanID == "" {
		return adapter.Effect{}, runError(generated.ErrorCodeApprovalRequired, "gate-human")
	}
	attribution := binding.Attribution
	humanID := approval.Acknowledgement.HumanID
	attribution.ResponsibleHumanPrincipalID = &humanID
	expected := store.RevisionToken{StateRevision: binding.Plan.Binding.StateRevision, RecoveryEpoch: binding.Plan.Binding.RecoveryEpoch}
	baseKey := []string{binding.Plan.PlanID, binding.Plan.PlanDigest, binding.Run.RunID, binding.Step.StepID, binding.Lease.LeaseID, binding.Step.OperationType, binding.Step.OperationID, binding.Step.ArtifactDigest}
	switch binding.Step.OperationType {
	case "gate.evidence.apply", "gate.evidence.supersede", "gate.evidence.revoke":
		draft, err := effect.repository.GetGateDraft(ctx, binding.Step.OperationID)
		if err != nil {
			return adapter.Effect{}, err
		}
		if draft.BundleDigest != binding.Step.ArtifactDigest || draft.SubjectID != binding.Step.TargetID || draft.RecoveryEpoch != expected.RecoveryEpoch || draft.StateRevision > expected.StateRevision {
			return adapter.Effect{}, runError(generated.ErrorCodePlanStale, "gate-draft")
		}
		expectedKind, status := "gate.evidence.apply", "applied"
		if draft.SupersedesEvidenceID != nil {
			expectedKind = "gate.evidence.supersede"
		}
		if draft.RevokesEvidenceID != nil {
			expectedKind, status = "gate.evidence.revoke", "revoked"
		}
		if expectedKind != binding.Step.OperationType {
			return adapter.Effect{}, runError(generated.ErrorCodePlanStale, "gate-relation")
		}
		profile, err := effect.repository.GetAppliedProfileScope(ctx)
		if err != nil {
			return adapter.Effect{}, err
		}
		var definition *generated.GateDefinition
		for index := range generated.GeneratedGateDefinitions {
			candidate := &generated.GeneratedGateDefinitions[index]
			if candidate.GateID == draft.GateID {
				definition = candidate
				break
			}
		}
		if definition == nil || definition.Applicability == "deferred" || (definition.ProfileID != nil && *definition.ProfileID != profile.ProfileID) || (definition.Applicability == "capability" && (definition.CapabilityID == nil || !slices.Contains(profile.Capabilities, *definition.CapabilityID))) || definition.DefinitionVersion != draft.DefinitionVersion || definition.EvaluatorVersion != draft.EvaluatorVersion {
			return adapter.Effect{}, runError(generated.ErrorCodePrerequisiteBlocked, "gate-definition")
		}
		observed, err := time.Parse(time.RFC3339, draft.Bundle.ObservedAt)
		if err != nil || observed.After(effect.clock().UTC()) {
			return adapter.Effect{}, runError(generated.ErrorCodeInputInvalid, "gate-observed-at")
		}
		expires := observed.Add(time.Duration(definition.FreshnessSeconds) * time.Second)
		if !expires.After(effect.clock().UTC()) {
			return adapter.Effect{}, runError(generated.ErrorCodePrerequisiteBlocked, "gate-evidence-stale")
		}
		request := store.GateApplyRequest{DraftID: draft.DraftID, EvidenceID: draft.EvidenceID, GateID: draft.GateID, SubjectID: draft.SubjectID, Expected: expected, PlanID: binding.Plan.PlanID, PlanDigest: binding.Plan.PlanDigest, RunID: binding.Run.RunID, StepID: binding.Step.StepID, LeaseID: binding.Lease.LeaseID, DeclarationID: binding.Plan.DeclarationID, DeclarationRevision: binding.Plan.Binding.DeclarationRevision, ReleaseBuildID: effect.releaseBuildID, ToolVersion: effect.toolVersion, ExpiresAt: expires.UTC().Truncate(time.Second).Format(time.RFC3339), SourceKind: draft.SourceKind, ProofClass: draft.ProofClass, Status: status, SupersedesEvidenceID: draft.SupersedesEvidenceID, RevokesEvidenceID: draft.RevokesEvidenceID, KeyDigest: coreGateDigest(append(baseKey, "key")...), RequestDigest: coreGateDigest(append(baseKey, "request", effect.releaseBuildID, effect.toolVersion, expires.Format(time.RFC3339), draft.SourceKind, draft.ProofClass)...), Attribution: attribution}
		applied, err := effect.repository.ApplyGateEvidence(ctx, request)
		if err != nil {
			return adapter.Effect{}, err
		}
		return adapter.Effect{Status: "succeeded", ResultDigest: applied.BundleDigest, Changed: true, EffectObserved: true}, nil
	case "gate.profile.bind":
		draft, err := effect.repository.GetProfileDraft(ctx, binding.Step.OperationID)
		if err != nil {
			return adapter.Effect{}, err
		}
		if draft.ScopeDigest != binding.Step.ArtifactDigest || draft.Scope.ProfileID != binding.Step.TargetID || draft.RecoveryEpoch != expected.RecoveryEpoch || draft.StateRevision > expected.StateRevision {
			return adapter.Effect{}, runError(generated.ErrorCodePlanStale, "profile-draft")
		}
		request := store.ProfileApplyRequest{BindingID: draft.BindingID, Scope: draft.Scope, Expected: expected, PlanID: binding.Plan.PlanID, PlanDigest: binding.Plan.PlanDigest, RunID: binding.Run.RunID, StepID: binding.Step.StepID, LeaseID: binding.Lease.LeaseID, DeclarationID: binding.Plan.DeclarationID, DeclarationRevision: binding.Plan.Binding.DeclarationRevision, KeyDigest: coreGateDigest(append(baseKey, "key")...), RequestDigest: coreGateDigest(append(baseKey, "request")...), Attribution: attribution}
		applied, err := effect.repository.ApplyProfileBinding(ctx, request)
		if err != nil {
			return adapter.Effect{}, err
		}
		if applied.ProfileID != draft.Scope.ProfileID {
			return adapter.Effect{}, runError(generated.ErrorCodeIntegrityFailure, "profile-binding")
		}
		return adapter.Effect{Status: "succeeded", ResultDigest: draft.ScopeDigest, Changed: true, EffectObserved: true}, nil
	default:
		return adapter.Effect{}, runError(generated.ErrorCodePrerequisiteBlocked, "gate-operation-unavailable")
	}
}

func (effect *CoreGateEffect) Verify(ctx context.Context, binding ExactStepBinding, result adapter.Effect) (adapter.Verification, error) {
	if adapter.ValidateEffect(result) != nil || result.Status != "succeeded" {
		return adapter.Verification{}, runError(generated.ErrorCodeIntegrityFailure, "gate-effect")
	}
	switch binding.Step.OperationType {
	case "gate.evidence.apply", "gate.evidence.supersede", "gate.evidence.revoke":
		draft, err := effect.repository.GetGateDraft(ctx, binding.Step.OperationID)
		if err != nil {
			return adapter.Verification{}, err
		}
		rows, err := effect.repository.ListAppliedGateEvidence(ctx, draft.GateID, draft.SubjectID)
		if err != nil {
			return adapter.Verification{}, err
		}
		for _, row := range rows {
			if row.EvidenceID == draft.EvidenceID && row.BundleDigest == result.ResultDigest && row.StateRevision == binding.Run.StateRevision+1 && row.RecoveryEpoch == binding.Run.RecoveryEpoch && row.DeclarationID == binding.Plan.DeclarationID {
				return adapter.Verification{Verified: true, Digest: result.ResultDigest}, nil
			}
		}
	case "gate.profile.bind":
		draft, err := effect.repository.GetProfileDraft(ctx, binding.Step.OperationID)
		if err != nil {
			return adapter.Verification{}, err
		}
		scope, err := effect.repository.GetAppliedProfileScope(ctx)
		if err != nil {
			return adapter.Verification{}, err
		}
		if scope.ProfileID == draft.Scope.ProfileID && scope.ProfileVersion == draft.Scope.ProfileVersion && scope.PolicyID == draft.Scope.PolicyID && scope.PolicyVersion == draft.Scope.PolicyVersion && scope.StateRevision == binding.Run.StateRevision+1 && draft.ScopeDigest == result.ResultDigest {
			return adapter.Verification{Verified: true, Digest: result.ResultDigest}, nil
		}
	}
	return adapter.Verification{Verified: false, Digest: result.ResultDigest}, errors.New("gate postcondition not observed")
}
