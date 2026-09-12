package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type PlanCommitRequest struct {
	Plan                      generated.Plan
	DesiredDeclaration        generated.DeclarationRevision
	SourceDeclarationRevision int64
	ReasonDigest              string
	CanonicalBytes            []byte
	Readable                  string
	Expected                  RevisionToken
	KeyDigest                 string
	RequestDigest             string
	Attribution               audit.Attribution
}

type PlanCommitResult struct {
	Plan      generated.Plan
	Canonical []byte
	Readable  string
	Commit    Commit
	Created   bool
}

type PlanRepository struct {
	store                    *Store
	testFailBeforePlanInsert func() error
}

func NewPlanRepository(store *Store) *PlanRepository { return &PlanRepository{store: store} }

func (repository *PlanRepository) GetDeclaration(ctx context.Context, declarationID string, revision int64) (generated.DeclarationRevision, error) {
	return NewDeclarationRepository(repository.store).GetRevision(ctx, declarationID, revision)
}

func (repository *PlanRepository) GetDeclarationReason(ctx context.Context, declarationID string, revision int64) (string, error) {
	return NewDeclarationRepository(repository.store).GetReasonDigest(ctx, declarationID, revision)
}

func (repository *PlanRepository) CurrentRevision(ctx context.Context) (RevisionToken, error) {
	var result RevisionToken
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&result.StateRevision, &result.RecoveryEpoch)
	})
	return result, err
}

func (repository *PlanRepository) ExistingPlan(ctx context.Context, keyDigest, requestDigest string) (PlanCommitResult, bool, error) {
	return repository.existing(ctx, keyDigest, requestDigest)
}

func (repository *PlanRepository) CommitDeclarationAndPlan(ctx context.Context, request PlanCommitRequest) (PlanCommitResult, error) {
	if repository == nil || repository.store == nil || request.Plan.Binding.PriorStateRevision != request.Expected.StateRevision || request.Plan.Binding.StateRevision != request.Expected.StateRevision+1 || request.Plan.Binding.RecoveryEpoch != request.Expected.RecoveryEpoch || request.SourceDeclarationRevision < 1 || len(request.CanonicalBytes) == 0 || request.Readable == "" {
		return PlanCommitResult{}, newStoreError(generated.ErrorCodeInputInvalid, "plan", false, nil)
	}
	desiredCanonical, desiredErr := json.Marshal(request.DesiredDeclaration)
	if desiredErr != nil || generated.ValidateContractJSON(generated.SchemaIDDeclarationRevision, desiredCanonical, generated.ContractExact) != nil || !validDeclarationContent(request.DesiredDeclaration, request.ReasonDigest) || request.DesiredDeclaration.Status != "committed" || request.DesiredDeclaration.DeclarationID != request.Plan.DeclarationID || request.DesiredDeclaration.Revision != request.Plan.Binding.DeclarationRevision || request.DesiredDeclaration.Revision != request.SourceDeclarationRevision+1 || request.DesiredDeclaration.StateRevision != request.Plan.Binding.StateRevision || request.DesiredDeclaration.RecoveryEpoch != request.Expected.RecoveryEpoch {
		return PlanCommitResult{}, newStoreError(generated.ErrorCodeInputInvalid, "desired-declaration", false, desiredErr)
	}
	canonical, err := json.Marshal(request.Plan)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDPlan, canonical, generated.ContractExact) != nil || generated.ValidatePlanTiming(request.Plan) != nil || string(canonical) != string(request.CanonicalBytes) || !validPlanDigests(request.Plan, request.Readable) {
		return PlanCommitResult{}, newStoreError(generated.ErrorCodeInputInvalid, "plan", false, err)
	}
	key := audit.IntentKey{Scope: "plan-create", KeyDigest: audit.Fingerprint(request.KeyDigest), RequestDigest: audit.Fingerprint(request.RequestDigest)}
	after := audit.Fingerprint(request.Plan.PlanDigest)
	event := audit.EventDraft{Type: "plan.created", CorrelationID: request.KeyDigest, Attribution: request.Attribution, Target: audit.Target{Kind: "plan", ID: request.Plan.PlanID}, After: &after}
	if audit.ValidateIntentKey(key) != nil || audit.ValidateEventDraft(event) != nil {
		return PlanCommitResult{}, newStoreError(generated.ErrorCodeInputInvalid, "plan", false, nil)
	}
	if existing, found, err := repository.existing(ctx, request.KeyDigest, request.RequestDigest); err != nil || found {
		return existing, err
	}
	result := PlanCommitResult{Plan: request.Plan, Canonical: append([]byte(nil), request.CanonicalBytes...), Readable: request.Readable}
	intent, err := repository.store.writeIntent(ctx, intentRequest{Expected: &request.Expected, Idempotency: key, Event: event}, func(ctx context.Context, transaction *sql.Tx) error {
		var contentDigest, reasonDigest, status string
		if err := transaction.QueryRowContext(ctx, `SELECT content_digest,reason_digest,status FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, request.Plan.DeclarationID, request.SourceDeclarationRevision).Scan(&contentDigest, &reasonDigest, &status); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return newStoreError(generated.ErrorCodeResourceNotFound, "declaration-revision", false, nil)
			}
			return err
		}
		var latest int64
		if err := transaction.QueryRowContext(ctx, `SELECT COALESCE(MAX(declaration_revision),0) FROM declaration_revisions WHERE declaration_id=?`, request.Plan.DeclarationID).Scan(&latest); err != nil {
			return err
		}
		if status != "draft" || latest != request.SourceDeclarationRevision || contentDigest != request.DesiredDeclaration.ContentDigest || reasonDigest != request.ReasonDigest {
			return newStoreError(generated.ErrorCodeStateConflict, "desired-declaration", false, nil)
		}
		if _, err := transaction.ExecContext(ctx, `INSERT INTO declaration_revisions(declaration_id,declaration_revision,declaration_type,state_revision,recovery_epoch,content_digest,reason_digest,status,canonical_bytes,created_at,created_by,agent_session_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, request.DesiredDeclaration.DeclarationID, request.DesiredDeclaration.Revision, request.DesiredDeclaration.DeclarationType, request.DesiredDeclaration.StateRevision, request.DesiredDeclaration.RecoveryEpoch, request.DesiredDeclaration.ContentDigest, request.ReasonDigest, request.DesiredDeclaration.Status, desiredCanonical, request.DesiredDeclaration.CreatedAt, request.DesiredDeclaration.CreatedBy, request.DesiredDeclaration.AgentSessionID); err != nil {
			return err
		}
		if repository.testFailBeforePlanInsert != nil {
			if err := repository.testFailBeforePlanInsert(); err != nil {
				return err
			}
		}
		_, err := transaction.ExecContext(ctx, `INSERT INTO immutable_plans(plan_id,plan_digest,declaration_id,declaration_revision,state_revision,recovery_epoch,observation_fingerprint,idempotency_key_digest,request_digest,canonical_bytes,readable_plan,readable_digest,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, request.Plan.PlanID, request.Plan.PlanDigest, request.Plan.DeclarationID, request.Plan.Binding.DeclarationRevision, request.Plan.Binding.StateRevision, request.Plan.Binding.RecoveryEpoch, request.Plan.Binding.ObservationFingerprint, request.KeyDigest, request.RequestDigest, request.CanonicalBytes, request.Readable, request.Plan.ReadableDigest, request.Plan.CreatedAt, request.Plan.ExpiresAt)
		return err
	})
	if err != nil {
		return PlanCommitResult{}, err
	}
	if !intent.Created {
		stored, getErr := repository.getByKey(ctx, request.KeyDigest)
		if getErr != nil {
			return PlanCommitResult{}, getErr
		}
		result = stored
	}
	result.Commit, result.Created = intent.Commit, intent.Created
	return result, nil
}

func validPlanDigests(plan generated.Plan, readable string) bool {
	readableSum := sha256.Sum256([]byte(readable))
	if plan.ReadableDigest != "sha256:"+hex.EncodeToString(readableSum[:]) {
		return false
	}
	copy := plan
	copy.PlanID, copy.PlanDigest = "", ""
	preimage, err := json.Marshal(copy)
	if err != nil {
		return false
	}
	planSum := sha256.Sum256(preimage)
	digest := "sha256:" + hex.EncodeToString(planSum[:])
	return plan.PlanDigest == digest && plan.PlanID == "plan-"+strings.TrimPrefix(digest, "sha256:")[:32]
}

func (repository *PlanRepository) existing(ctx context.Context, key, requestDigest string) (PlanCommitResult, bool, error) {
	var storedDigest string
	var canonical []byte
	var readable string
	var revision, epoch int64
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT request_digest,canonical_bytes,readable_plan,state_revision,recovery_epoch FROM immutable_plans WHERE idempotency_key_digest=?`, key).Scan(&storedDigest, &canonical, &readable, &revision, &epoch)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return PlanCommitResult{}, false, nil
	}
	if err != nil {
		return PlanCommitResult{}, false, err
	}
	if storedDigest != requestDigest {
		return PlanCommitResult{}, true, newStoreError(generated.ErrorCodeStateConflict, "plan-intent-key", false, nil)
	}
	var document generated.Plan
	if !decodeStoredPlan(canonical, readable, &document) {
		return PlanCommitResult{}, true, newStoreError(generated.ErrorCodeIntegrityFailure, "plan", false, nil)
	}
	return PlanCommitResult{Plan: document, Canonical: canonical, Readable: readable, Commit: Commit{Changed: false, StateRevision: revision, RecoveryEpoch: epoch}, Created: false}, true, nil
}

func (repository *PlanRepository) GetPlan(ctx context.Context, planID string) (PlanCommitResult, error) {
	return repository.get(ctx, `SELECT canonical_bytes,readable_plan FROM immutable_plans WHERE plan_id=?`, planID)
}

func (repository *PlanRepository) getByKey(ctx context.Context, key string) (PlanCommitResult, error) {
	return repository.get(ctx, `SELECT canonical_bytes,readable_plan FROM immutable_plans WHERE idempotency_key_digest=?`, key)
}

func (repository *PlanRepository) get(ctx context.Context, query string, argument any) (PlanCommitResult, error) {
	var canonical []byte
	var readable string
	err := repository.store.Read(ctx, func(tx ReadTx) error { return tx.queryRow(ctx, query, argument).Scan(&canonical, &readable) })
	if errors.Is(err, sql.ErrNoRows) {
		return PlanCommitResult{}, newStoreError(generated.ErrorCodeResourceNotFound, "plan", false, nil)
	}
	if err != nil {
		return PlanCommitResult{}, err
	}
	var document generated.Plan
	if !decodeStoredPlan(canonical, readable, &document) {
		return PlanCommitResult{}, newStoreError(generated.ErrorCodeIntegrityFailure, "plan", false, nil)
	}
	return PlanCommitResult{Plan: document, Canonical: canonical, Readable: readable}, nil
}

func decodeStoredPlan(canonical []byte, readable string, document *generated.Plan) bool {
	if json.Unmarshal(canonical, document) != nil || generated.ValidateContractJSON(generated.SchemaIDPlan, canonical, generated.ContractExact) != nil || generated.ValidatePlanTiming(*document) != nil || !validPlanDigests(*document, readable) {
		return false
	}
	reencoded, err := json.Marshal(document)
	return err == nil && string(reencoded) == string(canonical)
}
