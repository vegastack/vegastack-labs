package server

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
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
	clock                   func() time.Time
	backupReady, auditReady bool
}

type scheduleAdmission struct {
	repository    *store.ScheduleRepository
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
		status := schedule.PrerequisiteStatus{Requirement: requirement, State: "blocked", ObservedAt: now, RecoveryEpoch: revision.RecoveryEpoch}
		policy, policyErr := reader.policies.GetActivePolicy(ctx, requirement.PolicyID)
		if policyErr != nil || policy.Revision != requirement.PolicyRevision || policy.RecoveryEpoch != requirement.RecoveryEpoch || revision.RecoveryEpoch != requirement.RecoveryEpoch {
			statuses[index] = status
			continue
		}
		switch requirement.Kind {
		case "recovery-authority":
			if authority.Mode == "ready" && authority.RecoveryEpoch == requirement.RecoveryEpoch {
				status.State = "current"
			}
		case "observation-authority-current":
			if revision.StateRevision == policy.StateRevision {
				status.State = "current"
			}
		case "applicable-gate-current":
			profile, readErr := reader.gates.GetAppliedProfileScope(ctx)
			if readErr == nil && profile.RecoveryEpoch == requirement.RecoveryEpoch {
				current := true
				for _, gateID := range policy.ExactSourceIDs {
					evidence, evidenceErr := reader.gates.ListCurrentAppliedGateEvidence(ctx, gateID, requirement.SubjectID)
					current = current && evidenceErr == nil && len(evidence) > 0
				}
				if current {
					status.State = "current"
				}
			}
		case "local-backup-qualification":
			if !reader.backupReady {
				break
			}
			draft, readErr := reader.backups.GetBackupPolicyDraftByDigest(ctx, policy.RetentionRuleDigest, requirement.RecoveryEpoch)
			if readErr == nil && draft.PolicyID != "" && containsString(policy.ExactSourceIDs, draft.PolicyID) {
				status.State = "current"
			}
		case "retirement-certainty":
			backupStatus, readErr := reader.backups.ReadLocalBackupStatus(ctx)
			if readErr == nil && backupStatus.RecoveryEpoch == requirement.RecoveryEpoch && retirementCertain(backupStatus) {
				status.State = "current"
			}
		case "audit-chain-current":
			if !reader.auditReady {
				break
			}
			verification, readErr := reader.authority.VerifyAuditHistory(ctx, nil)
			if readErr == nil && verification.RecoveryEpoch == requirement.RecoveryEpoch && verification.Status != "incident" {
				status.State = "current"
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
func retirementCertain(status generated.BackupStatusData) bool {
	for _, item := range status.Retirements {
		if item.Status == "planned" || item.Status == "in-progress" || item.Status == "uncertain" {
			return false
		}
	}
	for _, item := range status.Offsite {
		if item.RetirementStatus != nil && (*item.RetirementStatus == "planned" || *item.RetirementStatus == "in-progress" || *item.RetirementStatus == "uncertain") {
			return false
		}
	}
	return true
}
