package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type RestorePlanRequest struct {
	Binding  generated.RestoreBinding
	Expected RevisionToken
}

type RestoreTransitionRequest struct {
	PlanID, From, To, PlanDigest, EvidenceDigest string
	Expected                                     RevisionToken
}

type RecoveryCandidateRequest struct {
	CandidateID, PlanID, CandidateDigest, PreservedAuthorityDigest                   string
	FenceSetDigest, AuditDecisionDigest, DatabaseDigest, JournalDigest, BundleDigest string
	Expected                                                                         RevisionToken
}

type RestoreSession struct {
	Binding   generated.RestoreBinding
	Status    string
	CreatedAt string
	Candidate *RecoveryCandidateRequest
}

type PendingRecoveryCandidate struct {
	Binding        generated.RestoreBinding
	DatabaseDigest string
	JournalDigest  string
	BundleDigest   string
}

func (repository *RestoreRepository) Qualification(ctx context.Context, planID string) (RestorePlanQualification, error) {
	if repository == nil || repository.store == nil || planID == "" {
		return RestorePlanQualification{}, restoreStoreError(generated.ErrorCodeInputInvalid, "restore-plan-qualification")
	}
	var result RestorePlanQualification
	var requestBytes, bindingBytes []byte
	var planDigest, sourceDigest, fenceDigest, auditDigest string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT plan_digest,request_bytes,binding_bytes,source_digest,fence_set_digest,audit_decision_digest FROM restore_plan_qualifications WHERE plan_id=?`, planID).Scan(&planDigest, &requestBytes, &bindingBytes, &sourceDigest, &fenceDigest, &auditDigest)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return result, restoreStoreError(generated.ErrorCodeResourceNotFound, "restore-plan-qualification")
	}
	if err != nil {
		return result, err
	}
	if json.Unmarshal(requestBytes, &result.Request) != nil || json.Unmarshal(bindingBytes, &result.Binding) != nil || !validRestorePlanQualification(result, generated.Plan{PlanID: planID, PlanDigest: planDigest}) || sourceDigest != result.Request.Source.VerificationDigest || fenceDigest != result.Request.FenceSetDigest || auditDigest != result.Request.AuditDecisionDigest {
		return RestorePlanQualification{}, restoreStoreError(generated.ErrorCodeIntegrityFailure, "restore-plan-qualification")
	}
	return result, nil
}

func validRestorePlanQualification(qualification RestorePlanQualification, plan generated.Plan) bool {
	request, binding := qualification.Request, qualification.Binding
	requestRaw, requestErr := json.Marshal(request)
	bindingRaw, bindingErr := json.Marshal(binding)
	if requestErr != nil || bindingErr != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreRequest, requestRaw, generated.ContractExact) != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreBinding, bindingRaw, generated.ContractExact) != nil || !validRestoreBinding(binding) || binding.PlanID != plan.PlanID || binding.PlanDigest != plan.PlanDigest || binding.HumanAcknowledgementID != "pending-human-acknowledgement" {
		return false
	}
	return restoreRequestMatchesBinding(request, binding)
}

func restoreRequestMatchesBinding(request generated.RestoreRequest, binding generated.RestoreBinding) bool {
	return equalRestoreSource(request.Source, binding.Source) && request.PointID == binding.PointID && request.TargetDigest == binding.TargetDigest && request.FenceSetDigest == binding.FenceSetDigest && request.AuditDecisionDigest == binding.AuditDecisionDigest && request.CandidateDigest == binding.CandidateDigest &&
		request.FormerHostID == binding.FormerHostID && request.ReplacementHostID == binding.ReplacementHostID && request.RecoveryDraftID == binding.RecoveryDraftID && request.CiphertextFingerprint == binding.CiphertextFingerprint && request.SourceAdmissionDigest == binding.SourceAdmissionDigest && request.FenceQualificationDigest == binding.FenceQualificationDigest &&
		request.RecoveryRunID == binding.RecoveryRunID && request.RecoveryStepID == binding.RecoveryStepID && request.RecoveryLeaseID == binding.RecoveryLeaseID && request.RecoveryChallengeID == binding.RecoveryChallengeID && request.RecoveryReceiptID == binding.RecoveryReceiptID &&
		request.CanaryRunID == binding.CanaryRunID && request.CanaryStepID == binding.CanaryStepID && request.CanaryLeaseID == binding.CanaryLeaseID && request.CanaryChallengeID == binding.CanaryChallengeID && request.CanaryReceiptID == binding.CanaryReceiptID && request.CanaryBindingDigest == binding.CanaryBindingDigest &&
		request.PriorInstanceID == binding.PriorInstanceID && request.NewInstanceID == binding.NewInstanceID && request.PriorRecoveryEpoch == binding.PriorRecoveryEpoch && request.NextRecoveryEpoch == binding.NextRecoveryEpoch && equalSortedStrings(request.DependencyIDs, binding.DependencyIDs) && equalSortedStrings(request.TargetIDs, binding.TargetIDs)
}

func equalRestoreSource(left, right generated.RestoreSourceBinding) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return string(a) == string(b)
}

func equalSortedStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	a, b := append([]string(nil), left...), append([]string(nil), right...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type RestoreRepository struct{ store *Store }

func NewRestoreRepository(store *Store) *RestoreRepository { return &RestoreRepository{store: store} }

func (repository *RestoreRepository) RecoveredAuthorityBundle(ctx context.Context, planID string) (RecoveredAuthorityBundle, string, error) {
	if repository == nil || repository.store == nil {
		return RecoveredAuthorityBundle{}, "", restoreStoreError(generated.ErrorCodeInputInvalid, "recovery-authority-bundle")
	}
	return repository.store.RecoveredAuthorityBundle(ctx, planID)
}

func (repository *RestoreRepository) CreatePlan(ctx context.Context, request RestorePlanRequest) (RestoreSession, error) {
	if repository == nil || repository.store == nil || !validRestoreBinding(request.Binding) || request.Expected.StateRevision < 0 || request.Expected.RecoveryEpoch < 0 {
		return RestoreSession{}, restoreStoreError(generated.ErrorCodeInputInvalid, "restore-plan")
	}
	raw, _ := json.Marshal(request.Binding)
	dependencyDigest := restoreDependencyDigest(request.Binding.Source.DependencyDigests)
	now := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	repository.store.mu.Lock()
	defer repository.store.mu.Unlock()
	transaction, err := repository.store.conn.BeginTx(ctx, nil)
	if err != nil {
		return RestoreSession{}, err
	}
	defer transaction.Rollback()
	if err := compareRestoreState(ctx, transaction, request.Expected, request.Binding.PriorInstanceID); err != nil {
		return RestoreSession{}, err
	}
	var planDigest, declarationID, acknowledgementID, acknowledgementStatus string
	var declarationRevision int64
	err = transaction.QueryRowContext(ctx, `SELECT p.plan_digest,p.declaration_id,p.declaration_revision,a.acknowledgement_id,a.status FROM immutable_plans p JOIN declaration_revisions d ON d.declaration_id=p.declaration_id AND d.declaration_revision=p.declaration_revision JOIN acknowledgement_requests a ON a.plan_id=p.plan_id AND a.acknowledgement_id=? WHERE p.plan_id=? AND p.recovery_epoch=? AND d.declaration_type='recovery.restore'`, request.Binding.HumanAcknowledgementID, request.Binding.PlanID, request.Expected.RecoveryEpoch).Scan(&planDigest, &declarationID, &declarationRevision, &acknowledgementID, &acknowledgementStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return RestoreSession{}, restoreStoreError(generated.ErrorCodePrerequisiteBlocked, "restore-plan")
	}
	if err != nil {
		return RestoreSession{}, err
	}
	if planDigest != request.Binding.PlanDigest || acknowledgementID != request.Binding.HumanAcknowledgementID || acknowledgementStatus != "approved" {
		return RestoreSession{}, restoreStoreError(generated.ErrorCodeStateConflict, "restore-plan")
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO restore_sessions(plan_id,plan_digest,declaration_id,declaration_revision,human_acknowledgement_id,point_id,point_digest,dependency_digest,fence_set_digest,audit_decision_digest,target_digest,candidate_digest,prior_instance_id,new_instance_id,prior_recovery_epoch,next_recovery_epoch,state_revision,binding_bytes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		request.Binding.PlanID, request.Binding.PlanDigest, declarationID, declarationRevision, request.Binding.HumanAcknowledgementID,
		request.Binding.PointID, request.Binding.Source.PointDigest, dependencyDigest, request.Binding.FenceSetDigest,
		request.Binding.AuditDecisionDigest, request.Binding.TargetDigest, request.Binding.CandidateDigest,
		request.Binding.PriorInstanceID, request.Binding.NewInstanceID, request.Binding.PriorRecoveryEpoch,
		request.Binding.NextRecoveryEpoch, request.Expected.StateRevision, raw, now)
	if err != nil {
		if existing, getErr := getRestoreSessionTx(ctx, transaction, request.Binding.PlanID); getErr == nil && equalRestoreBinding(existing.Binding, request.Binding) {
			return existing, nil
		}
		return RestoreSession{}, restoreStoreError(generated.ErrorCodeStateConflict, "restore-plan")
	}
	if err := transaction.Commit(); err != nil {
		return RestoreSession{}, err
	}
	return RestoreSession{Binding: request.Binding, Status: "planned", CreatedAt: now}, nil
}

func (repository *RestoreRepository) Get(ctx context.Context, planID string) (RestoreSession, error) {
	if repository == nil || repository.store == nil || planID == "" {
		return RestoreSession{}, restoreStoreError(generated.ErrorCodeInputInvalid, "restore-session")
	}
	var result RestoreSession
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		var err error
		result, err = getRestoreSessionRead(ctx, tx, planID)
		return err
	})
	return result, err
}

func (repository *RestoreRepository) ListRestoreStatusesScoped(ctx context.Context, scope authorization.ReadScope, snapshot RevisionToken, afterID string, limit int) ([]generated.BrowserRestoreStatus, RevisionToken, error) {
	if repository == nil || repository.store == nil || limit < 1 || limit > 101 {
		return nil, RevisionToken{}, restoreStoreError(generated.ErrorCodeInputInvalid, "restore-page")
	}
	var items []generated.BrowserRestoreStatus
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		if err := verifyExactReadSnapshot(ctx, tx, scope, snapshot); err != nil {
			return err
		}
		rows, err := tx.query(ctx, `SELECT s.plan_id FROM restore_sessions s JOIN read_grants g ON g.resource_id=s.plan_id AND g.principal_id=? AND g.capability=? AND g.resource_kind=? AND g.grant_revision=? AND g.status='active' WHERE s.plan_id>? ORDER BY s.plan_id LIMIT ?`, scope.PrincipalID, scope.Capability, scope.ResourceKind, scope.GrantRevision, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, id := range ids {
			stored, err := getRestoreSessionRead(ctx, tx, id)
			if err != nil {
				return err
			}
			verification := "pending"
			if stored.Status == "verified" {
				verification = "verified"
			}
			items = append(items, generated.BrowserRestoreStatus{Schema: generated.SchemaIDBrowserRestoreStatus, SchemaVersion: "1.0.0", PointID: stored.Binding.PointID, PlanID: stored.Binding.PlanID, PlanDigest: stored.Binding.PlanDigest, TargetDigest: stored.Binding.TargetDigest, Status: stored.Status, ReasonCode: "restore-" + stored.Status, RecoveryEpoch: stored.Binding.NextRecoveryEpoch, VerificationStatus: verification, SafeNextAction: restoreSafeNextActionForStore(stored.Status)})
		}
		return nil
	})
	return items, snapshot, err
}

func restoreSafeNextActionForStore(status string) string {
	switch status {
	case "verified":
		return "none"
	case "verification-required":
		return "verify the recovered authority"
	default:
		return "continue with the exact approved restore plan"
	}
}

// PendingPromotion returns the single exact candidate the next server startup
// may promote. More than one candidate is an integrity failure rather than a
// selection decision at startup.
func (repository *RestoreRepository) PendingPromotion(ctx context.Context) (PendingRecoveryCandidate, bool, error) {
	if repository == nil || repository.store == nil {
		return PendingRecoveryCandidate{}, false, restoreStoreError(generated.ErrorCodeInputInvalid, "recovery-candidate")
	}
	var result PendingRecoveryCandidate
	var raw []byte
	found := false
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		rows, err := tx.query(ctx, `SELECT s.binding_bytes,c.database_digest,c.journal_digest,c.bundle_digest
			FROM recovery_candidates c
			JOIN restore_sessions s ON s.plan_id=c.plan_id
			WHERE (SELECT t.to_status FROM restore_transitions t WHERE t.plan_id=c.plan_id ORDER BY t.transition_id DESC LIMIT 1)='verification-required'
			ORDER BY c.created_at,c.candidate_id LIMIT 2`)
		if err != nil {
			return err
		}
		defer rows.Close()
		if !rows.Next() {
			return rows.Err()
		}
		if err := rows.Scan(&raw, &result.DatabaseDigest, &result.JournalDigest, &result.BundleDigest); err != nil {
			return err
		}
		found = true
		if rows.Next() {
			return restoreStoreError(generated.ErrorCodeIntegrityFailure, "recovery-candidate")
		}
		return rows.Err()
	})
	if err != nil || !found {
		return PendingRecoveryCandidate{}, found, err
	}
	if json.Unmarshal(raw, &result.Binding) != nil || !validRestoreBinding(result.Binding) || !restoreDigest(result.DatabaseDigest) || !restoreDigest(result.JournalDigest) || !restoreDigest(result.BundleDigest) {
		return PendingRecoveryCandidate{}, false, restoreStoreError(generated.ErrorCodeIntegrityFailure, "recovery-candidate")
	}
	return result, true, nil
}

func (repository *RestoreRepository) AppendTransition(ctx context.Context, request RestoreTransitionRequest) error {
	if repository == nil || repository.store == nil || request.PlanID == "" || !restoreDigest(request.PlanDigest) || !restoreDigest(request.EvidenceDigest) || !allowedRestoreTransition(request.From, request.To) {
		return restoreStoreError(generated.ErrorCodeInputInvalid, "restore-transition")
	}
	repository.store.mu.Lock()
	defer repository.store.mu.Unlock()
	tx, err := repository.store.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var priorInstance, storedDigest string
	if err := tx.QueryRowContext(ctx, `SELECT prior_instance_id,plan_digest FROM restore_sessions WHERE plan_id=?`, request.PlanID).Scan(&priorInstance, &storedDigest); err != nil {
		return restoreStoreError(generated.ErrorCodeResourceNotFound, "restore-session")
	}
	if err := compareRestoreState(ctx, tx, request.Expected, priorInstance); err != nil {
		return err
	}
	if storedDigest != request.PlanDigest {
		return restoreStoreError(generated.ErrorCodeStateConflict, "restore-transition")
	}
	var current string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT to_status FROM restore_transitions WHERE plan_id=? ORDER BY transition_id DESC LIMIT 1),'planned')`, request.PlanID).Scan(&current); err != nil {
		return err
	}
	if current != request.From {
		if current == request.To {
			var planDigest, evidenceDigest string
			var stateRevision, recoveryEpoch int64
			if err := tx.QueryRowContext(ctx, `SELECT plan_digest,evidence_digest,state_revision,recovery_epoch FROM restore_transitions WHERE plan_id=? AND from_status=?`, request.PlanID, request.From).Scan(&planDigest, &evidenceDigest, &stateRevision, &recoveryEpoch); err == nil && planDigest == request.PlanDigest && evidenceDigest == request.EvidenceDigest && stateRevision == request.Expected.StateRevision && recoveryEpoch == request.Expected.RecoveryEpoch {
				return nil
			}
		}
		return restoreStoreError(generated.ErrorCodeStateConflict, "restore-transition")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO restore_transitions(plan_id,from_status,to_status,plan_digest,evidence_digest,state_revision,recovery_epoch,created_at) VALUES(?,?,?,?,?,?,?,?)`, request.PlanID, request.From, request.To, request.PlanDigest, request.EvidenceDigest, request.Expected.StateRevision, request.Expected.RecoveryEpoch, repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339))
	if err != nil {
		return restoreStoreError(generated.ErrorCodeStateConflict, "restore-transition")
	}
	return tx.Commit()
}

func (repository *RestoreRepository) BindCandidate(ctx context.Context, request RecoveryCandidateRequest) error {
	if repository == nil || repository.store == nil || request.CandidateID == "" || request.PlanID == "" || !restoreDigest(request.CandidateDigest) || !restoreDigest(request.PreservedAuthorityDigest) || !restoreDigest(request.FenceSetDigest) || !restoreDigest(request.AuditDecisionDigest) || !restoreDigest(request.DatabaseDigest) || !restoreDigest(request.JournalDigest) || !restoreDigest(request.BundleDigest) {
		return restoreStoreError(generated.ErrorCodeInputInvalid, "recovery-candidate")
	}
	repository.store.mu.Lock()
	defer repository.store.mu.Unlock()
	tx, err := repository.store.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var priorInstance, candidate, fence, decision string
	if err := tx.QueryRowContext(ctx, `SELECT prior_instance_id,candidate_digest,fence_set_digest,audit_decision_digest FROM restore_sessions WHERE plan_id=?`, request.PlanID).Scan(&priorInstance, &candidate, &fence, &decision); err != nil {
		return restoreStoreError(generated.ErrorCodeResourceNotFound, "restore-session")
	}
	if err := compareRestoreState(ctx, tx, request.Expected, priorInstance); err != nil {
		return err
	}
	if candidate != request.CandidateDigest || fence != request.FenceSetDigest || decision != request.AuditDecisionDigest {
		return restoreStoreError(generated.ErrorCodeStateConflict, "recovery-candidate")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO recovery_candidates(candidate_id,plan_id,candidate_digest,preserved_authority_digest,fence_set_digest,audit_decision_digest,database_digest,journal_digest,bundle_digest,state_revision,recovery_epoch,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, request.CandidateID, request.PlanID, request.CandidateDigest, request.PreservedAuthorityDigest, request.FenceSetDigest, request.AuditDecisionDigest, request.DatabaseDigest, request.JournalDigest, request.BundleDigest, request.Expected.StateRevision, request.Expected.RecoveryEpoch, repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339))
	if err != nil {
		var candidateDigest, preservedDigest, fenceDigest, auditDigest, databaseDigest, journalDigest, bundleDigest string
		var stateRevision, recoveryEpoch int64
		if getErr := tx.QueryRowContext(ctx, `SELECT candidate_digest,preserved_authority_digest,fence_set_digest,audit_decision_digest,database_digest,journal_digest,bundle_digest,state_revision,recovery_epoch FROM recovery_candidates WHERE plan_id=?`, request.PlanID).Scan(&candidateDigest, &preservedDigest, &fenceDigest, &auditDigest, &databaseDigest, &journalDigest, &bundleDigest, &stateRevision, &recoveryEpoch); getErr == nil && candidateDigest == request.CandidateDigest && preservedDigest == request.PreservedAuthorityDigest && fenceDigest == request.FenceSetDigest && auditDigest == request.AuditDecisionDigest && databaseDigest == request.DatabaseDigest && journalDigest == request.JournalDigest && bundleDigest == request.BundleDigest && stateRevision == request.Expected.StateRevision && recoveryEpoch == request.Expected.RecoveryEpoch {
			return nil
		}
		return restoreStoreError(generated.ErrorCodeStateConflict, "recovery-candidate")
	}
	return tx.Commit()
}

func compareRestoreState(ctx context.Context, tx *sql.Tx, expected RevisionToken, instance string) error {
	var revision, epoch int64
	var current, mode string
	if err := tx.QueryRowContext(ctx, `SELECT state_revision,recovery_epoch,instance_id,authority_mode FROM system_meta WHERE id=1`).Scan(&revision, &epoch, &current, &mode); err != nil {
		return err
	}
	if revision != expected.StateRevision || epoch != expected.RecoveryEpoch || current != instance || mode != "ready" {
		return restoreStoreError(generated.ErrorCodeStateConflict, "restore-authority")
	}
	return nil
}

func getRestoreSessionTx(ctx context.Context, tx *sql.Tx, planID string) (RestoreSession, error) {
	var raw []byte
	var result RestoreSession
	if err := tx.QueryRowContext(ctx, `SELECT binding_bytes,created_at FROM restore_sessions WHERE plan_id=?`, planID).Scan(&raw, &result.CreatedAt); err != nil {
		return result, err
	}
	if json.Unmarshal(raw, &result.Binding) != nil || !validRestoreBinding(result.Binding) {
		return RestoreSession{}, restoreStoreError(generated.ErrorCodeIntegrityFailure, "restore-session")
	}
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT to_status FROM restore_transitions WHERE plan_id=? ORDER BY transition_id DESC LIMIT 1),'planned')`, planID).Scan(&result.Status); err != nil {
		return RestoreSession{}, err
	}
	return result, nil
}

func getRestoreSessionRead(ctx context.Context, tx ReadTx, planID string) (RestoreSession, error) {
	var raw []byte
	var result RestoreSession
	err := tx.queryRow(ctx, `SELECT binding_bytes,created_at FROM restore_sessions WHERE plan_id=?`, planID).Scan(&raw, &result.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return result, restoreStoreError(generated.ErrorCodeResourceNotFound, "restore-session")
	}
	if err != nil {
		return result, err
	}
	if json.Unmarshal(raw, &result.Binding) != nil || !validRestoreBinding(result.Binding) {
		return RestoreSession{}, restoreStoreError(generated.ErrorCodeIntegrityFailure, "restore-session")
	}
	if err := tx.queryRow(ctx, `SELECT COALESCE((SELECT to_status FROM restore_transitions WHERE plan_id=? ORDER BY transition_id DESC LIMIT 1),'planned')`, planID).Scan(&result.Status); err != nil {
		return RestoreSession{}, err
	}
	var candidate RecoveryCandidateRequest
	err = tx.queryRow(ctx, `SELECT candidate_id,plan_id,candidate_digest,preserved_authority_digest,fence_set_digest,audit_decision_digest,database_digest,journal_digest,bundle_digest,state_revision,recovery_epoch FROM recovery_candidates WHERE plan_id=?`, planID).Scan(&candidate.CandidateID, &candidate.PlanID, &candidate.CandidateDigest, &candidate.PreservedAuthorityDigest, &candidate.FenceSetDigest, &candidate.AuditDecisionDigest, &candidate.DatabaseDigest, &candidate.JournalDigest, &candidate.BundleDigest, &candidate.Expected.StateRevision, &candidate.Expected.RecoveryEpoch)
	if err == nil {
		result.Candidate = &candidate
	} else if !errors.Is(err, sql.ErrNoRows) {
		return RestoreSession{}, err
	}
	return result, nil
}

func allowedRestoreTransition(from, to string) bool {
	if to == "failed" || to == "uncertain" {
		return from == "planned" || from == "fenced" || from == "restoring" || from == "verification-required"
	}
	return from == "planned" && to == "fenced" || from == "fenced" && to == "restoring" || from == "restoring" && to == "verification-required" || from == "verification-required" && to == "verified"
}

func validRestoreBinding(binding generated.RestoreBinding) bool {
	raw, err := json.Marshal(binding)
	return err == nil && generated.ValidateContractJSON(generated.SchemaIDRestoreBinding, raw, generated.ContractExact) == nil && binding.Status == "planned" && binding.PointID == binding.Source.PointID && binding.PriorRecoveryEpoch == binding.Source.RecoveryEpoch && binding.NextRecoveryEpoch == binding.PriorRecoveryEpoch+1 && binding.PriorInstanceID != binding.NewInstanceID && binding.FormerHostID != binding.ReplacementHostID
}

func equalRestoreBinding(left, right generated.RestoreBinding) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return string(a) == string(b)
}
func restoreDependencyDigest(values []string) string {
	values = append([]string(nil), values...)
	sort.Strings(values)
	raw, _ := json.Marshal(values)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func restoreDigest(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}
func restoreStoreError(code, resource string) error { return newStoreError(code, resource, false, nil) }
