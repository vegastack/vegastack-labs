package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type PlanCommitRequest struct {
	Plan           generated.Plan
	CanonicalBytes []byte
	Readable       string
	Expected       RevisionToken
	KeyDigest      string
	RequestDigest  string
	Attribution    audit.Attribution
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

func (repository *PlanRepository) CommitDeclarationAndPlan(ctx context.Context, request PlanCommitRequest) (PlanCommitResult, error) {
	if repository == nil || repository.store == nil || request.Plan.Binding.PriorStateRevision != request.Expected.StateRevision || request.Plan.Binding.StateRevision != request.Expected.StateRevision+1 || request.Plan.Binding.RecoveryEpoch != request.Expected.RecoveryEpoch || len(request.CanonicalBytes) == 0 || request.Readable == "" {
		return PlanCommitResult{}, newStoreError(generated.ErrorCodeInputInvalid, "plan", false, nil)
	}
	canonical, err := json.Marshal(request.Plan)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDPlan, canonical, generated.ContractExact) != nil || generated.ValidatePlanTiming(request.Plan) != nil || string(canonical) != string(request.CanonicalBytes) {
		return PlanCommitResult{}, newStoreError(generated.ErrorCodeInputInvalid, "plan", false, err)
	}
	key := audit.IntentKey{Scope: "plan-create", KeyDigest: audit.Fingerprint(request.KeyDigest), RequestDigest: audit.Fingerprint(request.RequestDigest)}
	after := audit.Fingerprint(request.Plan.PlanDigest)
	event := audit.EventDraft{Type: "plan.created", CorrelationID: request.KeyDigest, Attribution: request.Attribution, Target: audit.Target{Kind: "plan", ID: request.Plan.PlanID}, After: &after}
	if audit.ValidateIntentKey(key) != nil || audit.ValidateEventDraft(event) != nil {
		return PlanCommitResult{}, newStoreError(generated.ErrorCodeInputInvalid, "plan", false, nil)
	}
	result := PlanCommitResult{Plan: request.Plan, Canonical: append([]byte(nil), request.CanonicalBytes...), Readable: request.Readable}
	intent, err := repository.store.writeIntent(ctx, intentRequest{Expected: &request.Expected, Idempotency: key, Event: event}, func(ctx context.Context, transaction *sql.Tx) error {
		var contentDigest string
		if err := transaction.QueryRowContext(ctx, `SELECT content_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, request.Plan.DeclarationID, request.Plan.Binding.DeclarationRevision).Scan(&contentDigest); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return newStoreError(generated.ErrorCodeResourceNotFound, "declaration-revision", false, nil)
			}
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
	if json.Unmarshal(canonical, &document) != nil || generated.ValidateContractJSON(generated.SchemaIDPlan, canonical, generated.ContractCompatibleRead) != nil {
		return PlanCommitResult{}, newStoreError(generated.ErrorCodeIntegrityFailure, "plan", false, nil)
	}
	return PlanCommitResult{Plan: document, Canonical: canonical, Readable: readable}, nil
}
