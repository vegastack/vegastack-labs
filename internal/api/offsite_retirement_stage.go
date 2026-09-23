package api

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type OffsiteRetirementCatalogSource interface {
	CurrentOffsiteRetirementCatalog(context.Context) (backup.OffsiteRetirementCatalog, error)
}
type OffsiteRetirementStageService interface {
	DryRun(context.Context, generated.BackupOffsiteRetirementDryRunRequest, identity.Principal) (generated.BackupOffsiteRetirementDryRunData, error)
	Stage(context.Context, generated.BackupOffsiteRetirementStageRequest, identity.Principal) (generated.BackupOffsiteRetirementStageSubmission, error)
}

type localOffsiteSelectionSource interface {
	GetLocalRetirementIntentBySelection(context.Context, string) (store.LocalRetirementIntent, error)
}
type offsiteRetirementStager interface {
	StageOffsiteRetirement(context.Context, store.OffsiteRetirementIntent) (string, error)
}
type offsiteRetirementStageService struct {
	local       localOffsiteSelectionSource
	retirements offsiteRetirementStager
	catalogs    OffsiteRetirementCatalogSource
}

func NewOffsiteRetirementStageService(local localOffsiteSelectionSource, retirements offsiteRetirementStager, catalogs OffsiteRetirementCatalogSource) (OffsiteRetirementStageService, error) {
	if local == nil || retirements == nil || catalogs == nil {
		return nil, apiFailure(generated.ErrorCodeInputInvalid, "offsite-retirement-stage")
	}
	return &offsiteRetirementStageService{local: local, retirements: retirements, catalogs: catalogs}, nil
}

func (s *offsiteRetirementStageService) Stage(ctx context.Context, input generated.BackupOffsiteRetirementStageRequest, principal identity.Principal) (generated.BackupOffsiteRetirementStageSubmission, error) {
	var zero generated.BackupOffsiteRetirementStageSubmission
	raw, _ := json.Marshal(input)
	if generated.ValidateContractJSON(generated.SchemaIDBackupOffsiteRetirementStageRequest, raw, generated.ContractExact) != nil || !identity.ValidPrincipal(principal) || identity.EffectivePrincipalKind(principal) != identity.PrincipalHuman || input.LockAdminReferenceID == input.RetentionReferenceID {
		return zero, apiFailure(generated.ErrorCodeInputInvalid, "offsite-retirement-stage")
	}
	intent, candidate, err := s.derive(ctx, input.SelectionDigest, input.ExpectedStateRevision, input.RecoveryEpoch, input.OneOwnerProofID, input.LockAdminReferenceID, input.RetentionReferenceID, input.CredentialBindingDigest)
	if err != nil {
		return zero, err
	}
	intent.IntentID, intent.PlanID, intent.PlanDigest = "offsite-retirement-"+input.IdempotencyKey, input.PlanID, input.PlanDigest
	if input.TargetDigest != intent.IntentDigest {
		return zero, apiFailure(generated.ErrorCodePlanStale, "offsite-retirement-intent")
	}
	id, err := s.retirements.StageOffsiteRetirement(ctx, intent)
	if err != nil {
		return zero, err
	}
	return generated.BackupOffsiteRetirementStageSubmission{Schema: generated.SchemaIDBackupOffsiteRetirementStageSubmission, SchemaVersion: "1.1.0", IntentID: id, GenerationID: candidate.GenerationID, PointID: candidate.PointID, RuleSetDigest: candidate.RuleSetDigest, SurvivorRuleDigest: candidate.SurvivorRuleDigest, PreRuleCount: int64(candidate.PreRuleCount), SurvivorRuleCount: int64(candidate.SurvivorRuleCount), SurvivorPointIDs: candidate.SurvivorPointIDs, ExpectedReclaimBytes: candidate.ExpectedReclaimBytes, Status: "staged", StateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch}, nil
}

func (s *offsiteRetirementStageService) DryRun(ctx context.Context, input generated.BackupOffsiteRetirementDryRunRequest, principal identity.Principal) (generated.BackupOffsiteRetirementDryRunData, error) {
	var zero generated.BackupOffsiteRetirementDryRunData
	raw, _ := json.Marshal(input)
	if generated.ValidateContractJSON(generated.SchemaIDBackupOffsiteRetirementDryRunRequest, raw, generated.ContractExact) != nil || !identity.ValidPrincipal(principal) || identity.EffectivePrincipalKind(principal) != identity.PrincipalHuman || input.LockAdminReferenceID == input.RetentionReferenceID {
		return zero, apiFailure(generated.ErrorCodeInputInvalid, "offsite-retirement-dry-run")
	}
	intent, candidate, err := s.derive(ctx, input.SelectionDigest, input.ExpectedStateRevision, input.RecoveryEpoch, input.OneOwnerProofID, input.LockAdminReferenceID, input.RetentionReferenceID, input.CredentialBindingDigest)
	if err != nil {
		return zero, err
	}
	return generated.BackupOffsiteRetirementDryRunData{Schema: generated.SchemaIDBackupOffsiteRetirementDryRunData, SchemaVersion: "1.1.0", IntentDigest: intent.IntentDigest, SelectionDigest: input.SelectionDigest, CredentialBindingDigest: intent.CredentialBindingDigest, GenerationID: candidate.GenerationID, PointID: candidate.PointID, BucketID: candidate.BucketID, RuleSetDigest: candidate.RuleSetDigest, SurvivorRuleDigest: candidate.SurvivorRuleDigest, ManifestDigest: candidate.ManifestDigest, CatalogDigest: candidate.CatalogDigest, InventoryDigest: candidate.InventoryDigest, SurvivorPointIDs: candidate.SurvivorPointIDs, ObjectCount: int64(len(candidate.Objects)), ExpectedReclaimBytes: candidate.ExpectedReclaimBytes, PreRuleCount: int64(candidate.PreRuleCount), SurvivorRuleCount: int64(candidate.SurvivorRuleCount), StateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch}, nil
}

func (s *offsiteRetirementStageService) derive(ctx context.Context, selectionDigest string, revision, epoch int64, proofID, lockReference, retentionReference, credentialDigest string) (store.OffsiteRetirementIntent, backup.OffsiteRetirementCandidate, error) {
	local, err := s.local.GetLocalRetirementIntentBySelection(ctx, selectionDigest)
	if err != nil {
		return store.OffsiteRetirementIntent{}, backup.OffsiteRetirementCandidate{}, err
	}
	if local.Request.StateRevision != revision || local.Request.RecoveryEpoch != epoch {
		return store.OffsiteRetirementIntent{}, backup.OffsiteRetirementCandidate{}, apiFailure(generated.ErrorCodePlanStale, "offsite-retirement-selection")
	}
	catalog, err := s.catalogs.CurrentOffsiteRetirementCatalog(ctx)
	if err != nil {
		return store.OffsiteRetirementIntent{}, backup.OffsiteRetirementCandidate{}, apiFailure(generated.ErrorCodePrerequisiteBlocked, "offsite-retirement-qualified-catalog")
	}
	selection := backup.RetirementSelection{RecoveryEpoch: epoch}
	for _, v := range local.Request.Targets {
		selection.Targets = append(selection.Targets, backup.RetirementCandidate{PointID: v.PointID})
	}
	for _, v := range local.Request.Survivors {
		selection.Survivors = append(selection.Survivors, backup.RetirementCandidate{PointID: v.PointID})
	}
	candidate, err := backup.SelectOffsiteRetirement(catalog, selection, catalog.ObservedAt)
	if err != nil {
		return store.OffsiteRetirementIntent{}, candidate, apiFailure(generated.ErrorCodePrerequisiteBlocked, "offsite-retirement-dry-run")
	}
	intent := store.OffsiteRetirementIntent{GenerationID: candidate.GenerationID, PointID: candidate.PointID, BucketID: candidate.BucketID, RuleSetDigest: candidate.RuleSetDigest, SurvivorRuleDigest: candidate.SurvivorRuleDigest, ManifestDigest: candidate.ManifestDigest, CatalogDigest: candidate.CatalogDigest, InventoryDigest: candidate.InventoryDigest, OneOwnerProofID: proofID, LockAdminReferenceID: lockReference, RetentionReferenceID: retentionReference, CredentialBindingDigest: credentialDigest, SurvivorPointIDs: append([]string(nil), candidate.SurvivorPointIDs...), SourceRevision: candidate.SourceRevision, StateRevision: revision, RecoveryEpoch: epoch, MaxWorkObjects: candidate.MaxWorkObjects, MaxMutationBytes: candidate.MaxMutationBytes, PreRuleCount: candidate.PreRuleCount, SurvivorRuleCount: candidate.SurvivorRuleCount}
	intent.G008BundleDigest, intent.QualificationDigest, intent.PutCutoffDigest, intent.MultipartCutoffDigest, intent.ExclusiveAdminDigest = candidate.G008BundleDigest, candidate.QualificationDigest, candidate.PutCutoffDigest, candidate.MultipartCutoffDigest, candidate.ExclusiveAdminDigest
	for _, v := range candidate.Rules {
		intent.Rules = append(intent.Rules, store.OffsiteRetirementRule{RuleID: v.RuleID, Prefix: v.Prefix})
	}
	for _, v := range candidate.Objects {
		intent.Objects = append(intent.Objects, store.OffsiteRetirementObject{Key: v.Key, Digest: v.Digest, Bytes: v.Bytes})
	}
	intent.IntentDigest, _, err = store.OffsiteRetirementIntentDigests(intent)
	return intent, candidate, err
}

type UnavailableOffsiteRetirementCatalogSource struct{}

func (UnavailableOffsiteRetirementCatalogSource) CurrentOffsiteRetirementCatalog(context.Context) (backup.OffsiteRetirementCatalog, error) {
	return backup.OffsiteRetirementCatalog{}, errors.New("qualified G-008 offsite retirement catalog unavailable")
}
