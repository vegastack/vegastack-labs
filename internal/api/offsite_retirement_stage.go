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
	if generated.ValidateContractJSON(generated.SchemaIDBackupOffsiteRetirementStageRequest, raw, generated.ContractExact) != nil || !identity.ValidPrincipal(principal) || identity.EffectivePrincipalKind(principal) != identity.PrincipalHuman || input.LockAdminConsumerID == input.RetentionConsumerID {
		return zero, apiFailure(generated.ErrorCodeInputInvalid, "offsite-retirement-stage")
	}
	local, err := s.local.GetLocalRetirementIntentBySelection(ctx, input.SelectionDigest)
	if err != nil {
		return zero, err
	}
	if local.Request.StateRevision != input.ExpectedStateRevision || local.Request.RecoveryEpoch != input.RecoveryEpoch {
		return zero, apiFailure(generated.ErrorCodePlanStale, "offsite-retirement-selection")
	}
	catalog, err := s.catalogs.CurrentOffsiteRetirementCatalog(ctx)
	if err != nil {
		return zero, apiFailure(generated.ErrorCodePrerequisiteBlocked, "offsite-retirement-qualified-catalog")
	}
	selection := backup.RetirementSelection{RecoveryEpoch: local.Request.RecoveryEpoch}
	for _, v := range local.Request.Targets {
		selection.Targets = append(selection.Targets, backup.RetirementCandidate{PointID: v.PointID})
	}
	for _, v := range local.Request.Survivors {
		selection.Survivors = append(selection.Survivors, backup.RetirementCandidate{PointID: v.PointID})
	}
	candidate, err := backup.SelectOffsiteRetirement(catalog, selection, catalog.ObservedAt)
	if err != nil {
		return zero, apiFailure(generated.ErrorCodePrerequisiteBlocked, "offsite-retirement-dry-run")
	}
	if input.TargetDigest != candidate.CatalogDigest {
		return zero, apiFailure(generated.ErrorCodePlanStale, "offsite-retirement-catalog")
	}
	intent := store.OffsiteRetirementIntent{IntentID: "offsite-retirement-" + input.IdempotencyKey, PlanID: input.PlanID, PlanDigest: input.PlanDigest, GenerationID: candidate.GenerationID, PointID: candidate.PointID, BucketID: candidate.BucketID, RuleSetDigest: candidate.RuleSetDigest, SurvivorRuleDigest: candidate.SurvivorRuleDigest, ManifestDigest: candidate.ManifestDigest, CatalogDigest: candidate.CatalogDigest, InventoryDigest: candidate.InventoryDigest, OneOwnerProofID: input.OneOwnerProofID, LockAdminConsumerID: input.LockAdminConsumerID, RetentionConsumerID: input.RetentionConsumerID, SurvivorPointIDs: append([]string(nil), candidate.SurvivorPointIDs...), SourceRevision: candidate.SourceRevision, StateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch, MaxWorkObjects: candidate.MaxWorkObjects, MaxMutationBytes: candidate.MaxMutationBytes, PreRuleCount: candidate.PreRuleCount, SurvivorRuleCount: candidate.SurvivorRuleCount}
	for _, v := range candidate.Rules {
		intent.Rules = append(intent.Rules, store.OffsiteRetirementRule{RuleID: v.RuleID, Prefix: v.Prefix})
	}
	for _, v := range candidate.Objects {
		intent.Objects = append(intent.Objects, store.OffsiteRetirementObject{Key: v.Key, Digest: v.Digest, Bytes: v.Bytes})
	}
	id, err := s.retirements.StageOffsiteRetirement(ctx, intent)
	if err != nil {
		return zero, err
	}
	return generated.BackupOffsiteRetirementStageSubmission{Schema: generated.SchemaIDBackupOffsiteRetirementStageSubmission, SchemaVersion: "1.1.0", IntentID: id, GenerationID: candidate.GenerationID, PointID: candidate.PointID, RuleSetDigest: candidate.RuleSetDigest, SurvivorRuleDigest: candidate.SurvivorRuleDigest, PreRuleCount: int64(candidate.PreRuleCount), SurvivorRuleCount: int64(candidate.SurvivorRuleCount), SurvivorPointIDs: candidate.SurvivorPointIDs, ExpectedReclaimBytes: candidate.ExpectedReclaimBytes, Status: "staged", StateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch}, nil
}

type UnavailableOffsiteRetirementCatalogSource struct{}

func (UnavailableOffsiteRetirementCatalogSource) CurrentOffsiteRetirementCatalog(context.Context) (backup.OffsiteRetirementCatalog, error) {
	return backup.OffsiteRetirementCatalog{}, errors.New("qualified G-008 offsite retirement catalog unavailable")
}
