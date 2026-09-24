package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/schedule"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type scheduledActionResolver struct {
	backups     *store.BackupRepository
	audit       *store.Store
	credentials *store.CredentialRepository
	policies    *store.ScheduleRepository
}

func (resolver scheduledActionResolver) ResolveScheduledAction(ctx context.Context, policy generated.ScheduledJobPolicy, jobID string) (schedule.ActionBinding, []generated.ContractExtension, error) {
	action, err := schedule.BuildAction(policy)
	if err != nil {
		return action, nil, err
	}
	switch policy.ActionKind {
	case "backup-create", "backup-integrity-verify":
		action.OperationID = fmt.Sprintf("%s-operation-1", jobID)
		draft, readErr := resolver.backups.GetBackupPolicyDraftByDigest(ctx, policy.RetentionRuleDigest, policy.RecoveryEpoch)
		var backupPolicy generated.BackupPolicy
		if readErr != nil || json.Unmarshal([]byte(draft.CanonicalJSON), &backupPolicy) != nil || backupPolicy.RecoveryEpoch != policy.RecoveryEpoch || backupPolicy.EncryptionKeyReferenceID == nil || len(policy.CredentialReferenceIDs) != 1 || policy.CredentialReferenceIDs[0] != *backupPolicy.EncryptionKeyReferenceID || !containsString(policy.ExactSourceIDs, backupPolicy.PolicyID) || !containsString(policy.ExactSourceIDs, backupPolicy.SourceID) {
			return action, nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "scheduled-backup-policy", false)
		}
		action.ArtifactDigest = draft.Digest
		if policy.ActionKind == "backup-create" {
			if policy.ExactTargetIDs[0] != backupPolicy.RestoreTargetID {
				return action, nil, failure.New(generated.ErrorCodeAuthorizationDenied, "scheduled-backup-target", false)
			}
			action.InputDigest = draft.Digest
		} else {
			point, pointErr := resolver.backups.GetPendingRecoveryPoint(ctx, policy.ExactTargetIDs[0])
			if pointErr != nil || point.PolicyDigest != draft.Digest || point.RecoveryEpoch != policy.RecoveryEpoch {
				return action, nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "scheduled-backup-point", false)
			}
			action.InputDigest, action.ArtifactDigest = point.ManifestDigest, point.InventoryDigest
		}
		reference, referenceErr := resolver.credentials.GetReference(ctx, policy.CredentialReferenceIDs[0])
		if referenceErr != nil || reference.Status != "active" || reference.ActivatedAt == nil || reference.ConsumerID != "local.backup" || reference.PurposeID != "backup-encryption" || reference.TargetID != policy.ExactTargetIDs[0] || reference.RecoveryEpoch != policy.RecoveryEpoch || reference.StateRevision > policy.StateRevision || !containsString(reference.VerifiedConsumerIDs, "local.backup") {
			return action, nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "scheduled-backup-credential", false)
		}
		binding := credentialref.StepBinding{OperationID: action.OperationID, AdapterID: action.AdapterID, TargetID: policy.ExactTargetIDs[0], ReferenceID: reference.ReferenceID, ConsumerID: reference.ConsumerID, PurposeID: reference.PurposeID, MaterialVersion: reference.MaterialVersion, ResolverID: reference.ResolverID, StateRevision: policy.StateRevision, RecoveryEpoch: policy.RecoveryEpoch}
		return action, []generated.ContractExtension{{Name: "x-backup-policy", ValueDigest: draft.Digest}, {Name: "x-scheduled-credential-bindings", ValueDigest: credentialref.ManifestDigest([]credentialref.StepBinding{binding})}}, nil
	case "audit-checkpoint-export":
		if len(policy.ExactSourceIDs) != 1 {
			return action, nil, failure.New(generated.ErrorCodeAuthorizationDenied, "scheduled-audit-source", false)
		}
		checkpoint, readErr := resolver.audit.GetAuditCheckpoint(ctx, policy.ExactSourceIDs[0])
		authority, authorityErr := resolver.audit.CurrentAuthority(ctx)
		if readErr != nil || authorityErr != nil || checkpoint.Status != "pending" || checkpoint.RecoveryEpoch != policy.RecoveryEpoch || checkpoint.InstanceID != authority.InstanceID || policy.ExactTargetIDs[0] != authority.InstanceID || len(policy.CredentialReferenceIDs) != 1 || policy.CredentialReferenceIDs[0] != checkpoint.SignerReferenceID {
			return action, nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "scheduled-audit-checkpoint", false)
		}
		action.OperationID, action.InputDigest, action.ArtifactDigest = checkpoint.CheckpointID, checkpoint.ChainDigest, checkpoint.ChainDigest
		return action, []generated.ContractExtension{{Name: "x-audit-checkpoint", ValueDigest: checkpoint.ChainDigest}}, nil
	default:
		action.InputDigest = policy.RetentionRuleDigest
		action.ArtifactDigest = policy.RetentionRuleDigest
		return action, nil, nil
	}
}

func (resolver scheduledActionResolver) CommitScheduledAction(ctx context.Context, plan generated.Plan) error {
	manifest := ""
	policyDigest := ""
	for _, extension := range plan.Extensions {
		if extension.Name == "x-scheduled-credential-bindings" {
			manifest = extension.ValueDigest
		}
		if extension.Name == "x-scheduled-policy" {
			policyDigest = extension.ValueDigest
		}
	}
	if manifest == "" {
		return nil
	}
	policy, err := resolver.policies.GetActivePolicyByDigest(ctx, policyDigest)
	if err != nil || len(plan.Operations) != 1 || len(policy.CredentialReferenceIDs) != 1 {
		return failure.New(generated.ErrorCodePlanStale, "scheduled-credential-policy", false)
	}
	reference, err := resolver.credentials.GetReference(ctx, policy.CredentialReferenceIDs[0])
	if err != nil {
		return err
	}
	operation := plan.Operations[0]
	binding := credentialref.StepBinding{OperationID: operation.OperationID, AdapterID: operation.AdapterID, TargetID: operation.TargetID, ReferenceID: reference.ReferenceID, ConsumerID: reference.ConsumerID, PurposeID: reference.PurposeID, MaterialVersion: reference.MaterialVersion, ResolverID: reference.ResolverID, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch}
	// The operation ID contributes to the manifest, so the exact final digest is
	// checked here rather than trusting the preparation placeholder.
	if credentialref.ManifestDigest([]credentialref.StepBinding{binding}) != manifest {
		return failure.New(generated.ErrorCodeIntegrityFailure, "scheduled-credential-manifest", false)
	}
	return resolver.credentials.CommitScheduledStepBinding(ctx, plan, binding)
}
