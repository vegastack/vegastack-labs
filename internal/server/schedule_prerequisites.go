package server

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/schedule"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// schedulePrerequisiteReader projects only current typed repository facts. It
// never upgrades missing or uncertain evidence into authority.
type schedulePrerequisiteReader struct {
	authority               *store.Store
	policies                *store.ScheduleRepository
	gates                   *store.GateRepository
	backups                 *store.BackupRepository
	offsite                 recovery.SQLOffsiteSourceReader
	clock                   func() time.Time
	backupReady, auditReady bool
}

type scheduleAdmission struct {
	repository    *store.ScheduleRepository
	declarations  *store.DeclarationRepository
	authorizer    schedule.ScheduledAuthorizer
	principalID   string
	prerequisites schedulePrerequisiteReader
}

func (admission scheduleAdmission) ValidateScheduledPlan(ctx context.Context, plan generated.Plan, now time.Time) error {
	if err := admission.repository.ValidateScheduledPlan(ctx, plan, now); err != nil {
		return err
	}
	digest := ""
	for _, extension := range plan.Extensions {
		if extension.Name == "x-scheduled-policy" {
			digest = extension.ValueDigest
		}
	}
	policy, err := admission.repository.GetActivePolicyByDigest(ctx, digest)
	if err != nil {
		return err
	}
	if admission.declarations == nil || admission.authorizer == nil || admission.principalID == "" {
		return failure.New(generated.ErrorCodePrerequisiteBlocked, "scheduled-authority", false)
	}
	declaration, err := admission.declarations.GetRevision(ctx, policy.DeclarationID, policy.DeclarationRevision)
	if err != nil || declaration.Status != "committed" || declaration.StateRevision != plan.Binding.StateRevision || declaration.RecoveryEpoch != plan.Binding.RecoveryEpoch || declaration.DeclarationID != plan.DeclarationID || declaration.Revision != plan.Binding.DeclarationRevision {
		return failure.New(generated.ErrorCodePlanStale, "scheduled-declaration", false)
	}
	decision, err := admission.authorizer.AuthorizeScheduled(ctx, admission.principalID, plan)
	if err != nil || !decision.Allowed || decision.Branch == nil || *decision.Branch != "preauthorized" || decision.GrantRevision != policy.GrantRevision || decision.RecoveryEpoch != policy.RecoveryEpoch || decision.PlanDigest != plan.PlanDigest {
		return failure.New(generated.ErrorCodeAuthorizationDenied, "scheduled-current-grant", false)
	}
	statuses, err := admission.prerequisites.Current(ctx, schedule.Requirements(policy))
	if err != nil {
		return err
	}
	if err := schedule.RequireCurrent(statuses, now); err != nil {
		return failure.New(generated.ErrorCodePrerequisiteBlocked, "scheduled-prerequisite", false)
	}
	return nil
}

func (admission scheduleAdmission) ValidateCurrent(ctx context.Context, plan generated.Plan) error {
	return admission.ValidateScheduledPlan(ctx, plan, time.Now().UTC().Truncate(time.Second))
}

func (reader schedulePrerequisiteReader) Current(ctx context.Context, requirements []schedule.PrerequisiteRequirement) ([]schedule.PrerequisiteStatus, error) {
	now := reader.clock().UTC().Truncate(time.Second)
	revision, err := reader.policies.CurrentScheduleRevision(ctx)
	if err != nil {
		return nil, err
	}
	authority, err := reader.authority.CurrentAuthority(ctx)
	if err != nil {
		return nil, err
	}
	statuses := make([]schedule.PrerequisiteStatus, len(requirements))
	for index, requirement := range requirements {
		status := schedule.PrerequisiteStatus{Requirement: requirement, State: "blocked", RecoveryEpoch: revision.RecoveryEpoch}
		policy, policyErr := reader.policies.GetActivePolicy(ctx, requirement.PolicyID)
		if policyErr != nil || policy.Revision != requirement.PolicyRevision || policy.RecoveryEpoch != requirement.RecoveryEpoch || revision.RecoveryEpoch != requirement.RecoveryEpoch {
			statuses[index] = status
			continue
		}
		switch requirement.Kind {
		case "recovery-authority":
			if authority.Mode == "ready" && authority.RecoveryEpoch == requirement.RecoveryEpoch {
				status.State, status.ObservedAt = "current", now
			}
		case "observation-authority-current":
			if revision.StateRevision == policy.StateRevision {
				status.State, status.ObservedAt = "current", now
			}
		case "applicable-gate-current":
			profile, readErr := reader.gates.GetAppliedProfileScope(ctx)
			if readErr == nil && profile.RecoveryEpoch == requirement.RecoveryEpoch {
				current, oldest := true, now
				for _, gateID := range policy.ExactSourceIDs {
					evidence, evidenceErr := reader.gates.ListCurrentAppliedGateEvidence(ctx, gateID, requirement.SubjectID)
					if evidenceErr != nil || len(evidence) != 1 {
						current = false
						break
					}
					observed, parseErr := time.Parse(time.RFC3339, evidence[0].ObservedAt)
					if parseErr != nil || evidence[0].ProofClass != "live" || evidence[0].RecoveryEpoch != requirement.RecoveryEpoch || evidence[0].PolicyVersion != policy.PolicyVersion {
						current = false
						break
					}
					if observed.Before(oldest) {
						oldest = observed
					}
				}
				if current {
					status.State, status.ObservedAt = "current", oldest
				}
			}
		case "local-backup-qualification", "retirement-certainty":
			if !reader.backupReady {
				break
			}
			draft, readErr := reader.backups.GetBackupPolicyDraftByDigest(ctx, policy.RetentionRuleDigest, requirement.RecoveryEpoch)
			var backupPolicy generated.BackupPolicy
			if readErr != nil || json.Unmarshal([]byte(draft.CanonicalJSON), &backupPolicy) != nil || !containsString(policy.ExactSourceIDs, backupPolicy.PolicyID) {
				break
			}
			qualified, readErr := reader.backups.CurrentQualifiedLocalLastGood(ctx, backupPolicy.RepositoryClass, requirement.RecoveryEpoch, now)
			if readErr != nil {
				break
			}
			proofObserved := qualified.ObservedAt
			if backupPolicy.RepositoryClass == "critical" {
				offsite, offsiteErr := reader.offsite.CurrentOffsiteRecoverySource(ctx, qualified.PointID)
				if offsiteErr != nil || offsite.CurrentStateRevision != policy.StateRevision || offsite.CurrentRecoveryEpoch != requirement.RecoveryEpoch {
					break
				}
				if offsite.VerifiedAt.Before(proofObserved) {
					proofObserved = offsite.VerifiedAt
				}
			}
			if requirement.Kind == "local-backup-qualification" {
				status.State, status.ObservedAt = "current", proofObserved
				break
			}
			observed, certaintyErr := reader.backups.CurrentRetirementCertainty(ctx, backupPolicy.RepositoryClass, qualified.PointID, requirement.RecoveryEpoch, proofObserved)
			if certaintyErr == nil {
				status.State, status.ObservedAt = "current", observed
			}
		case "audit-chain-current":
			if !reader.auditReady {
				break
			}
			verification, readErr := reader.authority.VerifyAuditHistory(ctx, nil)
			if readErr == nil && verification.RecoveryEpoch == requirement.RecoveryEpoch && verification.Status != "incident" {
				status.State, status.ObservedAt = "current", now
			}
		}
		statuses[index] = status
	}
	return statuses, nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
