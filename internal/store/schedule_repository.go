package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/schedule"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

type ScheduledPolicyDraft struct {
	DraftID, CanonicalJSON, Digest, CreatedAt, CreatedByHumanID string
	Policy                                                      generated.ScheduledJobPolicy
}

type ScheduleActivationRequest struct {
	DraftID, AuthorizationBranch, ExecutingOperation, PlanID, PlanDigest, AcknowledgementID, ApprovedByHumanID string
	Expected                                                                                                   RevisionToken
	Attribution                                                                                                audit.Attribution
}

type OccurrenceClaim struct {
	Policy          generated.ScheduledJobPolicy
	ScheduledAt     time.Time
	WindowClosesAt  time.Time
	OccurrenceToken string
	TargetDigest    string
	IdempotencyKey  string
	Expected        RevisionToken
}

type ScheduledAttempt struct {
	AttemptID, JobID, Status, PlanID, RunID string
	Attempt                                 int64
	EffectStarted                           bool
	RecordedAt                              time.Time
}

type ScheduleRepository struct{ store *Store }

func NewScheduleRepository(authority *Store) *ScheduleRepository {
	return &ScheduleRepository{store: authority}
}

func (repository *ScheduleRepository) CurrentScheduleRevision(ctx context.Context) (schedule.Revision, error) {
	var result schedule.Revision
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&result.StateRevision, &result.RecoveryEpoch)
	})
	return result, err
}

func (repository *ScheduleRepository) ClaimScheduledOccurrence(ctx context.Context, policy generated.ScheduledJobPolicy, slot schedule.Slot, token, targetDigest, idempotencyKey string, revision schedule.Revision) (generated.ScheduledJob, error) {
	return repository.ClaimOccurrence(ctx, OccurrenceClaim{Policy: policy, ScheduledAt: slot.ScheduledAt, WindowClosesAt: slot.WindowClosesAt, OccurrenceToken: token, TargetDigest: targetDigest, IdempotencyKey: idempotencyKey, Expected: RevisionToken{StateRevision: revision.StateRevision, RecoveryEpoch: revision.RecoveryEpoch}})
}

func (repository *ScheduleRepository) TransitionScheduledOccurrence(ctx context.Context, jobID, from, to, reason string, planID, runID *string) (generated.ScheduledJob, error) {
	return repository.TransitionOccurrence(ctx, jobID, from, to, reason, planID, runID)
}

func (repository *ScheduleRepository) AppendScheduledAttempt(ctx context.Context, jobID string, attempt int64, status, planID, runID string, effectStarted bool, recordedAt time.Time) error {
	return repository.AppendAttempt(ctx, ScheduledAttempt{JobID: jobID, Attempt: attempt, Status: status, PlanID: planID, RunID: runID, EffectStarted: effectStarted, RecordedAt: recordedAt})
}

func scheduleDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func scheduleError(code, target string) error { return newStoreError(code, target, false, nil) }

func (repository *ScheduleRepository) StageDraft(ctx context.Context, policy generated.ScheduledJobPolicy, attribution audit.Attribution) (ScheduledPolicyDraft, error) {
	canonical, digest, err := schedule.CanonicalPolicy(policy)
	if err != nil || attribution.AuthenticatedPrincipalID == "" || attribution.AuthenticatedPrincipalMethod == "" {
		return ScheduledPolicyDraft{}, scheduleError(generated.ErrorCodeInputInvalid, "scheduled-policy-draft")
	}
	draft := ScheduledPolicyDraft{DraftID: "schedule-draft-" + digest[7:39], CanonicalJSON: string(canonical), Digest: digest, CreatedByHumanID: attribution.AuthenticatedPrincipalID, Policy: policy}
	draft.CreatedAt = repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	err = repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var stateRevision, recoveryEpoch int64
		if err := tx.QueryRowContext(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&stateRevision, &recoveryEpoch); err != nil {
			return err
		}
		if stateRevision+1 != policy.StateRevision || recoveryEpoch != policy.RecoveryEpoch {
			return scheduleError(generated.ErrorCodeStateConflict, "scheduled-policy-revision")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO scheduled_policy_drafts(draft_id,policy_id,policy_revision,canonical_json,policy_digest,created_by_human_id,state_revision,recovery_epoch,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, draft.DraftID, policy.PolicyID, policy.Revision, draft.CanonicalJSON, draft.Digest, draft.CreatedByHumanID, stateRevision, recoveryEpoch, draft.CreatedAt)
		if err != nil {
			var existingDigest string
			if scanErr := tx.QueryRowContext(ctx, `SELECT policy_digest FROM scheduled_policy_drafts WHERE draft_id=?`, draft.DraftID).Scan(&existingDigest); scanErr == nil && existingDigest == draft.Digest {
				return nil
			}
			return classifySQLiteError(ctx, err)
		}
		return nil
	})
	return draft, err
}

func (repository *ScheduleRepository) GetDraft(ctx context.Context, draftID string) (ScheduledPolicyDraft, error) {
	var result ScheduledPolicyDraft
	var canonical string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT draft_id,canonical_json,policy_digest,created_at,created_by_human_id FROM scheduled_policy_drafts WHERE draft_id=?`, draftID).Scan(&result.DraftID, &canonical, &result.Digest, &result.CreatedAt, &result.CreatedByHumanID)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return result, scheduleError(generated.ErrorCodeResourceNotFound, "scheduled-policy-draft")
	}
	if err != nil {
		return result, err
	}
	result.CanonicalJSON = canonical
	if scheduleDigest(canonical) != result.Digest || json.Unmarshal([]byte(canonical), &result.Policy) != nil {
		return ScheduledPolicyDraft{}, scheduleError(generated.ErrorCodeIntegrityFailure, "scheduled-policy-draft")
	}
	return result, nil
}

// Activate requires the exact executing human-branch activation step. The
// caller cannot turn a preauthorized occurrence into activation authority.
func (repository *ScheduleRepository) Activate(ctx context.Context, request ScheduleActivationRequest) (generated.ScheduledJobPolicy, error) {
	draft, err := repository.GetDraft(ctx, request.DraftID)
	if err != nil {
		return generated.ScheduledJobPolicy{}, err
	}
	policy := draft.Policy
	if request.AuthorizationBranch != "human" || request.ExecutingOperation != "schedule.policy.activate" || request.PlanID == "" || request.PlanDigest == "" || request.AcknowledgementID == "" || request.Expected.StateRevision != policy.StateRevision || request.Expected.RecoveryEpoch != policy.RecoveryEpoch || request.ApprovedByHumanID == "" || request.Attribution.ResponsibleHumanPrincipalID == nil || *request.Attribution.ResponsibleHumanPrincipalID != request.ApprovedByHumanID {
		return generated.ScheduledJobPolicy{}, scheduleError(generated.ErrorCodeAuthorizationDenied, "scheduled-policy-activation")
	}
	now := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	err = repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var stateRevision, recoveryEpoch int64
		if err := tx.QueryRowContext(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&stateRevision, &recoveryEpoch); err != nil {
			return err
		}
		if request.Expected != (RevisionToken{StateRevision: stateRevision, RecoveryEpoch: recoveryEpoch}) {
			return scheduleError(generated.ErrorCodePlanStale, "scheduled-policy-activation")
		}
		var declarationID, storedDigest, authorizationBranch, executorMode string
		var declarationRevision, planStateRevision, planRecoveryEpoch int64
		if err := tx.QueryRowContext(ctx, `SELECT declaration_id,declaration_revision,plan_digest,state_revision,recovery_epoch,json_extract(canonical_bytes,'$.authorizationBranch'),json_extract(canonical_bytes,'$.executorMode') FROM immutable_plans WHERE plan_id=?`, request.PlanID).Scan(&declarationID, &declarationRevision, &storedDigest, &planStateRevision, &planRecoveryEpoch, &authorizationBranch, &executorMode); err != nil {
			return scheduleError(generated.ErrorCodeAuthorizationDenied, "scheduled-policy-activation-plan")
		}
		if declarationID != policy.DeclarationID || declarationRevision != policy.DeclarationRevision || storedDigest != request.PlanDigest || planStateRevision != stateRevision || planRecoveryEpoch != recoveryEpoch || authorizationBranch != "human" || executorMode != "central" {
			return scheduleError(generated.ErrorCodeAuthorizationDenied, "scheduled-policy-activation-plan")
		}
		activationID := "schedule-activation-" + draft.Digest[7:39]
		_, err := tx.ExecContext(ctx, `INSERT INTO scheduled_policy_activations(activation_id,draft_id,policy_id,policy_revision,status,approval_plan_id,approval_plan_digest,acknowledgement_id,approved_by_human_id,state_revision,recovery_epoch,activated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, activationID, draft.DraftID, policy.PolicyID, policy.Revision, "active", request.PlanID, request.PlanDigest, request.AcknowledgementID, request.ApprovedByHumanID, stateRevision, recoveryEpoch, now)
		if err != nil {
			return classifySQLiteError(ctx, err)
		}
		return nil
	})
	return policy, err
}

func (repository *ScheduleRepository) ListRecoverableOccurrences(ctx context.Context) ([]generated.ScheduledJob, error) {
	var ids []string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		rows, err := tx.query(ctx, `SELECT o.job_id FROM scheduled_occurrences o JOIN scheduled_occurrence_transitions t ON t.transition_id=(SELECT MAX(t2.transition_id) FROM scheduled_occurrence_transitions t2 WHERE t2.job_id=o.job_id) WHERE t.to_status IN ('queued','running','retry-wait') ORDER BY o.created_at,o.job_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	jobs := make([]generated.ScheduledJob, 0, len(ids))
	for _, id := range ids {
		job, err := repository.GetOccurrence(ctx, id)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func (repository *ScheduleRepository) LatestScheduledAttempt(ctx context.Context, jobID string) (schedule.AttemptRecord, bool, error) {
	var attempt ScheduledAttempt
	var effect int
	var recorded string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT attempt_id,job_id,attempt,status,COALESCE(plan_id,''),COALESCE(run_id,''),effect_started,recorded_at FROM scheduled_occurrence_attempts WHERE job_id=? ORDER BY attempt DESC LIMIT 1`, jobID).Scan(&attempt.AttemptID, &attempt.JobID, &attempt.Attempt, &attempt.Status, &attempt.PlanID, &attempt.RunID, &effect, &recorded)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return schedule.AttemptRecord{}, false, nil
	}
	if err == nil {
		attempt.RecordedAt, err = time.Parse(time.RFC3339, recorded)
	}
	attempt.EffectStarted = effect != 0
	return schedule.AttemptRecord{Attempt: attempt.Attempt, RecordedAt: attempt.RecordedAt}, err == nil, err
}

func (repository *ScheduleRepository) ReleaseExpiredOccurrenceLeases(ctx context.Context, now time.Time) error {
	return repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM scheduled_occurrence_leases WHERE expires_at<=?`, now.UTC().Truncate(time.Second).Format(time.RFC3339))
		return err
	})
}

func (repository *ScheduleRepository) GetActivePolicy(ctx context.Context, policyID string) (generated.ScheduledJobPolicy, error) {
	var canonical string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT d.canonical_json FROM scheduled_policy_activations a JOIN scheduled_policy_drafts d ON d.draft_id=a.draft_id WHERE a.policy_id=? AND a.status='active' ORDER BY a.policy_revision DESC LIMIT 1`, policyID).Scan(&canonical)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return generated.ScheduledJobPolicy{}, scheduleError(generated.ErrorCodeResourceNotFound, "scheduled-policy")
	}
	var policy generated.ScheduledJobPolicy
	if err != nil || json.Unmarshal([]byte(canonical), &policy) != nil {
		if err != nil {
			return policy, err
		}
		return policy, scheduleError(generated.ErrorCodeIntegrityFailure, "scheduled-policy")
	}
	if _, _, err := schedule.CanonicalPolicy(policy); err != nil {
		return policy, scheduleError(generated.ErrorCodeIntegrityFailure, "scheduled-policy")
	}
	return policy, nil
}

func (repository *ScheduleRepository) GetActivePolicyApprover(ctx context.Context, policyID string, revision int64) (string, error) {
	var humanID string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT approved_by_human_id FROM scheduled_policy_activations WHERE policy_id=? AND policy_revision=? AND status='active'`, policyID, revision).Scan(&humanID)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return "", scheduleError(generated.ErrorCodeResourceNotFound, "scheduled-policy-approval")
	}
	return humanID, err
}

func (repository *ScheduleRepository) GetActivePolicyByDigest(ctx context.Context, digest string) (generated.ScheduledJobPolicy, error) {
	var policyID string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT a.policy_id FROM scheduled_policy_activations a JOIN scheduled_policy_drafts d ON d.draft_id=a.draft_id WHERE d.policy_digest=? AND a.status='active' ORDER BY a.policy_revision DESC LIMIT 1`, digest).Scan(&policyID)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return generated.ScheduledJobPolicy{}, scheduleError(generated.ErrorCodeResourceNotFound, "scheduled-policy")
	}
	if err != nil {
		return generated.ScheduledJobPolicy{}, err
	}
	return repository.GetActivePolicy(ctx, policyID)
}

func (repository *ScheduleRepository) ClaimOccurrence(ctx context.Context, claim OccurrenceClaim) (generated.ScheduledJob, error) {
	if claim.Policy.PolicyID == "" || claim.ScheduledAt.IsZero() || claim.WindowClosesAt.IsZero() || !claim.WindowClosesAt.After(claim.ScheduledAt) || claim.OccurrenceToken == "" || claim.IdempotencyKey == "" || claim.Expected.StateRevision != claim.Policy.StateRevision || claim.Expected.RecoveryEpoch != claim.Policy.RecoveryEpoch {
		return generated.ScheduledJob{}, scheduleError(generated.ErrorCodeInputInvalid, "scheduled-occurrence")
	}
	when := claim.ScheduledAt.UTC().Truncate(time.Second).Format(time.RFC3339)
	windowCloses := claim.WindowClosesAt.UTC().Truncate(time.Second).Format(time.RFC3339)
	jobID := "scheduled-job-" + scheduleDigest(fmt.Sprintf("%s\x00%d\x00%s", claim.Policy.PolicyID, claim.Policy.Revision, when))[7:39]
	now := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	err := repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO scheduled_occurrences(job_id,policy_id,policy_revision,scheduled_at,window_closes_at,occurrence_token_digest,target_digest,idempotency_key_digest,state_revision,recovery_epoch,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, jobID, claim.Policy.PolicyID, claim.Policy.Revision, when, windowCloses, scheduleDigest(claim.OccurrenceToken), claim.TargetDigest, scheduleDigest(claim.IdempotencyKey), claim.Expected.StateRevision, claim.Expected.RecoveryEpoch, now)
		if err != nil {
			return fmt.Errorf("occurrence insert: %w", err)
		}
		_, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO scheduled_occurrence_transitions(job_id,from_status,to_status,reason_code,recorded_at) VALUES(?,'new','queued','due',?)`, jobID, now)
		if err != nil {
			return fmt.Errorf("transition insert: %w", err)
		}
		return nil
	})
	if err != nil {
		return generated.ScheduledJob{}, err
	}
	return repository.GetOccurrence(ctx, jobID)
}

func (repository *ScheduleRepository) ScheduledOccurrenceDigest(ctx context.Context, jobID string) (string, error) {
	var policyID, scheduledAt, windowClosesAt, tokenDigest, targetDigest, keyDigest string
	var policyRevision, stateRevision, recoveryEpoch int64
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT policy_id,policy_revision,scheduled_at,window_closes_at,occurrence_token_digest,target_digest,idempotency_key_digest,state_revision,recovery_epoch FROM scheduled_occurrences WHERE job_id=?`, jobID).Scan(&policyID, &policyRevision, &scheduledAt, &windowClosesAt, &tokenDigest, &targetDigest, &keyDigest, &stateRevision, &recoveryEpoch)
	})
	if err != nil {
		return "", err
	}
	value := struct {
		JobID, PolicyID                                                                        string
		PolicyRevision                                                                         int64
		ScheduledAt, WindowClosesAt, OccurrenceTokenDigest, TargetDigest, IdempotencyKeyDigest string
		StateRevision, RecoveryEpoch                                                           int64
	}{jobID, policyID, policyRevision, scheduledAt, windowClosesAt, tokenDigest, targetDigest, keyDigest, stateRevision, recoveryEpoch}
	bytes, _, err := stateexport.CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	return scheduleDigest(string(bytes)), nil
}

func (repository *ScheduleRepository) ScheduledOccurrenceWindowClosesAt(ctx context.Context, jobID string) (time.Time, error) {
	var value string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT window_closes_at FROM scheduled_occurrences WHERE job_id=?`, jobID).Scan(&value)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, scheduleError(generated.ErrorCodeResourceNotFound, "scheduled-occurrence")
	}
	if err != nil {
		return time.Time{}, err
	}
	result, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, scheduleError(generated.ErrorCodeIntegrityFailure, "scheduled-occurrence-window")
	}
	return result, nil
}

func (repository *ScheduleRepository) GetOccurrence(ctx context.Context, jobID string) (generated.ScheduledJob, error) {
	var job generated.ScheduledJob
	var planID, runID sql.NullString
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT o.job_id,o.policy_id,o.policy_revision,o.scheduled_at,COALESCE((SELECT MAX(attempt) FROM scheduled_occurrence_attempts WHERE job_id=o.job_id),1),t.plan_id,t.run_id,t.to_status,t.reason_code,o.recovery_epoch FROM scheduled_occurrences o JOIN scheduled_occurrence_transitions t ON t.transition_id=(SELECT MAX(transition_id) FROM scheduled_occurrence_transitions WHERE job_id=o.job_id) WHERE o.job_id=?`, jobID).Scan(&job.JobID, &job.PolicyID, &job.PolicyRevision, &job.ScheduledAt, &job.Attempt, &planID, &runID, &job.Status, &job.ReasonCode, &job.RecoveryEpoch)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return job, scheduleError(generated.ErrorCodeResourceNotFound, "scheduled-occurrence")
	}
	if err != nil {
		return job, err
	}
	job.Schema, job.SchemaVersion = generated.SchemaIDScheduledJob, "1.1.0"
	if planID.Valid {
		job.PlanID = &planID.String
	}
	if runID.Valid {
		job.RunID = &runID.String
	}
	return job, nil
}

// ValidateScheduledPlan rebinds a generated occurrence plan to current durable
// policy and occurrence state immediately before admission and again before an
// adapter effect. The policy digest covers sources, subjects, targets, work
// bound, credentials, grant, revision, epoch, expiry, and retry/window rules.
func (repository *ScheduleRepository) ValidateScheduledPlan(ctx context.Context, plan generated.Plan, now time.Time) error {
	policyDigest, occurrenceDigest := "", ""
	for _, extension := range plan.Extensions {
		switch extension.Name {
		case "x-scheduled-policy":
			if policyDigest != "" {
				return scheduleError(generated.ErrorCodeIntegrityFailure, "scheduled-plan-extension")
			}
			policyDigest = extension.ValueDigest
		case "x-scheduled-occurrence":
			if occurrenceDigest != "" {
				return scheduleError(generated.ErrorCodeIntegrityFailure, "scheduled-plan-extension")
			}
			occurrenceDigest = extension.ValueDigest
		}
	}
	if policyDigest == "" || occurrenceDigest == "" || plan.AuthorizationBranch != "preauthorized" || plan.ExecutorMode != "central" {
		return scheduleError(generated.ErrorCodeAuthorizationDenied, "scheduled-plan")
	}
	var jobID, leaseExpiry string
	var attempt int64
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT o.job_id,a.attempt,l.expires_at FROM scheduled_occurrences o JOIN scheduled_occurrence_transitions t ON t.transition_id=(SELECT MAX(t2.transition_id) FROM scheduled_occurrence_transitions t2 WHERE t2.job_id=o.job_id) JOIN scheduled_occurrence_attempts a ON a.attempt_id=(SELECT a2.attempt_id FROM scheduled_occurrence_attempts a2 WHERE a2.job_id=o.job_id ORDER BY a2.attempt DESC LIMIT 1) JOIN scheduled_occurrence_leases l ON l.job_id=o.job_id WHERE t.plan_id=? AND t.to_status='running' AND a.plan_id=?`, plan.PlanID, plan.PlanID).Scan(&jobID, &attempt, &leaseExpiry)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return scheduleError(generated.ErrorCodePlanStale, "scheduled-occurrence")
	}
	if err != nil {
		return err
	}
	leaseDeadline, err := time.Parse(time.RFC3339, leaseExpiry)
	if err != nil || !now.UTC().Before(leaseDeadline) || attempt <= 0 {
		return scheduleError(generated.ErrorCodePlanStale, "scheduled-lease")
	}
	job, err := repository.GetOccurrence(ctx, jobID)
	if err != nil {
		return err
	}
	current, err := repository.CurrentScheduleRevision(ctx)
	if err != nil || current.StateRevision != plan.Binding.StateRevision || current.RecoveryEpoch != plan.Binding.RecoveryEpoch {
		return scheduleError(generated.ErrorCodePlanStale, "scheduled-current-revision")
	}
	currentOccurrenceDigest, err := repository.ScheduledOccurrenceDigest(ctx, jobID)
	if err != nil || currentOccurrenceDigest != occurrenceDigest {
		return scheduleError(generated.ErrorCodePlanStale, "scheduled-occurrence-digest")
	}
	policy, err := repository.GetActivePolicy(ctx, job.PolicyID)
	if err != nil {
		return err
	}
	_, currentDigest, err := schedule.CanonicalPolicy(policy)
	if err != nil || currentDigest != policyDigest || job.PolicyRevision != policy.Revision || job.RecoveryEpoch != policy.RecoveryEpoch || plan.Binding.StateRevision != policy.StateRevision || plan.Binding.RecoveryEpoch != policy.RecoveryEpoch {
		return scheduleError(generated.ErrorCodePlanStale, "scheduled-policy")
	}
	expires, err := time.Parse(time.RFC3339, policy.ExpiresAt)
	if err != nil || !now.UTC().Before(expires) {
		return scheduleError(generated.ErrorCodePlanStale, "scheduled-policy")
	}
	action, err := schedule.BuildAction(policy)
	if err != nil || int64(len(plan.Operations)) != action.MaximumWork || len(plan.Operations) != len(action.TargetIDs) {
		return scheduleError(generated.ErrorCodeAuthorizationDenied, "scheduled-work-bound")
	}
	for index, operation := range plan.Operations {
		if operation.Sequence != int64(index+1) || operation.OperationType != action.OperationType || operation.AdapterID != action.AdapterID || operation.TargetID != action.TargetIDs[index] || !operation.Idempotent {
			return scheduleError(generated.ErrorCodeAuthorizationDenied, "scheduled-operation-binding")
		}
		if policy.ActionKind == "backup-integrity-verify" {
			point, pointErr := NewBackupRepository(repository.store).GetPendingRecoveryPoint(ctx, operation.TargetID)
			if pointErr != nil || point.PolicyDigest != policy.RetentionRuleDigest || point.RecoveryEpoch != policy.RecoveryEpoch || operation.InputDigest != point.ManifestDigest || operation.ArtifactDigest != point.InventoryDigest {
				return scheduleError(generated.ErrorCodeAuthorizationDenied, "scheduled-backup-point-binding")
			}
		}
		if !scheduledOperationDigests(policy, plan.Extensions, operation) {
			return scheduleError(generated.ErrorCodeAuthorizationDenied, "scheduled-operation-digest")
		}
	}
	return nil
}

func scheduledOperationDigests(policy generated.ScheduledJobPolicy, extensions []generated.ContractExtension, operation generated.PlanOperation) bool {
	extension := func(name string) string {
		for _, item := range extensions {
			if item.Name == name {
				return item.ValueDigest
			}
		}
		return ""
	}
	switch policy.ActionKind {
	case "gate-check", "observation-refresh":
		return operation.InputDigest == policy.RetentionRuleDigest && operation.ArtifactDigest == policy.RetentionRuleDigest
	case "backup-create":
		return extension("x-backup-policy") == policy.RetentionRuleDigest && operation.InputDigest == policy.RetentionRuleDigest && operation.ArtifactDigest == policy.RetentionRuleDigest
	case "backup-integrity-verify":
		return extension("x-backup-policy") == policy.RetentionRuleDigest
	case "audit-checkpoint-export":
		checkpoint := extension("x-audit-checkpoint")
		return checkpoint != "" && operation.InputDigest == checkpoint && operation.ArtifactDigest == checkpoint
	default:
		return false
	}
}

func (repository *ScheduleRepository) TransitionOccurrence(ctx context.Context, jobID, from, to, reason string, planID, runID *string) (generated.ScheduledJob, error) {
	if generated.ValidatePhase5Transition("scheduled-job", from, to) != nil || reason == "" {
		return generated.ScheduledJob{}, scheduleError(generated.ErrorCodeInputInvalid, "scheduled-transition")
	}
	now := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	err := repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var current string
		if err := tx.QueryRowContext(ctx, `SELECT to_status FROM scheduled_occurrence_transitions WHERE job_id=? ORDER BY transition_id DESC LIMIT 1`, jobID).Scan(&current); err != nil {
			return err
		}
		if current != from {
			return scheduleError(generated.ErrorCodeStateConflict, "scheduled-transition")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO scheduled_occurrence_transitions(job_id,from_status,to_status,reason_code,plan_id,run_id,recorded_at) VALUES(?,?,?,?,?,?,?)`, jobID, from, to, reason, planID, runID, now)
		if err != nil {
			return classifySQLiteError(ctx, err)
		}
		return nil
	})
	if err != nil {
		return generated.ScheduledJob{}, err
	}
	return repository.GetOccurrence(ctx, jobID)
}

func (repository *ScheduleRepository) AppendAttempt(ctx context.Context, attempt ScheduledAttempt) error {
	if attempt.JobID == "" || attempt.Attempt <= 0 {
		return scheduleError(generated.ErrorCodeInputInvalid, "scheduled-attempt")
	}
	if attempt.AttemptID == "" {
		attempt.AttemptID = fmt.Sprintf("%s-attempt-%d", attempt.JobID, attempt.Attempt)
	}
	if attempt.RecordedAt.IsZero() {
		attempt.RecordedAt = repository.store.config.Clock().UTC().Truncate(time.Second)
	}
	return repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO scheduled_occurrence_attempts(attempt_id,job_id,attempt,status,plan_id,run_id,effect_started,recorded_at) VALUES(?,?,?,?,?,?,?,?)`, attempt.AttemptID, attempt.JobID, attempt.Attempt, attempt.Status, nullableScheduleString(attempt.PlanID), nullableScheduleString(attempt.RunID), attempt.EffectStarted, attempt.RecordedAt.Format(time.RFC3339))
		if err != nil {
			return classifySQLiteError(ctx, err)
		}
		return nil
	})
}

func (repository *ScheduleRepository) AcquireOccurrenceLease(ctx context.Context, jobID, leaseID, holderID string, expiresAt time.Time) error {
	if jobID == "" || leaseID == "" || holderID == "" || !expiresAt.After(repository.store.config.Clock()) {
		return scheduleError(generated.ErrorCodeInputInvalid, "scheduled-lease")
	}
	now := repository.store.config.Clock().UTC().Truncate(time.Second)
	return repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var existingExpiry string
		err := tx.QueryRowContext(ctx, `SELECT expires_at FROM scheduled_occurrence_leases WHERE job_id=?`, jobID).Scan(&existingExpiry)
		if err == nil {
			deadline, parseErr := time.Parse(time.RFC3339, existingExpiry)
			if parseErr != nil || now.Before(deadline) {
				return scheduleError(generated.ErrorCodeStateConflict, "scheduled-lease")
			}
			if _, err = tx.ExecContext(ctx, `DELETE FROM scheduled_occurrence_leases WHERE job_id=?`, jobID); err != nil {
				return err
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO scheduled_occurrence_leases(job_id,lease_id,holder_id,acquired_at,expires_at) VALUES(?,?,?,?,?)`, jobID, leaseID, holderID, now.Format(time.RFC3339), expiresAt.UTC().Truncate(time.Second).Format(time.RFC3339))
		if err != nil {
			return classifySQLiteError(ctx, err)
		}
		return nil
	})
}

func (repository *ScheduleRepository) ReleaseOccurrenceLease(ctx context.Context, jobID, leaseID string) error {
	return repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `DELETE FROM scheduled_occurrence_leases WHERE job_id=? AND lease_id=?`, jobID, leaseID)
		if err != nil {
			return err
		}
		count, _ := result.RowsAffected()
		if count != 1 {
			return scheduleError(generated.ErrorCodeStateConflict, "scheduled-lease")
		}
		return nil
	})
}

func nullableScheduleString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func (repository *ScheduleRepository) inTx(ctx context.Context, business func(context.Context, *sql.Tx) error) error {
	if repository == nil || repository.store == nil {
		return scheduleError(generated.ErrorCodeInputInvalid, "schedule-repository")
	}
	repository.store.mu.Lock()
	defer repository.store.mu.Unlock()
	if err := repository.store.readyForTransaction(ctx); err != nil {
		return err
	}
	tx, err := repository.store.conn.BeginTx(ctx, nil)
	if err != nil {
		return repository.store.transactionError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := business(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return repository.store.transactionError(ctx, err)
	}
	return nil
}
