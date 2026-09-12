package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type AcknowledgementRepository struct{ store *Store }

func NewAcknowledgementRepository(store *Store) *AcknowledgementRepository {
	return &AcknowledgementRepository{store: store}
}

func (repository *AcknowledgementRepository) Create(ctx context.Context, record acknowledgement.CreateRecord) (acknowledgement.Stored, bool, error) {
	if repository == nil || repository.store == nil || record.CreatedAt.IsZero() || record.CreatedAt.Location() != time.UTC || record.Attribution.AuthenticatedPrincipalID != record.Request.HumanID || !validAcknowledgementCreate(record) {
		return acknowledgement.Stored{}, false, newStoreError(generated.ErrorCodeInputInvalid, "acknowledgement-request", false, nil)
	}
	if existing, err := repository.Get(ctx, record.Request.PlanID); err == nil {
		return existing, false, nil
	} else if Code(err) != generated.ErrorCodeResourceNotFound {
		return acknowledgement.Stored{}, false, err
	}
	requestBytes, _ := json.Marshal(record.Request)
	pendingBytes, _ := json.Marshal(record.Pending)
	after := audit.Fingerprint(record.Request.PlanDigest)
	event := audit.EventDraft{Type: "acknowledgement.requested", CorrelationID: record.Pending.AcknowledgementID, Attribution: record.Attribution, Target: audit.Target{Kind: "plan", ID: record.Request.PlanID}, After: &after}
	key := audit.IntentKey{Scope: "acknowledgement-request", KeyDigest: audit.Fingerprint(hashText(record.Pending.AcknowledgementID)), RequestDigest: audit.Fingerprint(hashBytes(requestBytes))}
	result, err := repository.store.executeAuditIntent(ctx, intentRequest{Expected: &RevisionToken{StateRevision: record.Request.StateRevision, RecoveryEpoch: record.Request.RecoveryEpoch}, Idempotency: key, Event: event}, false, func(ctx context.Context, transaction *sql.Tx) error {
		var digest string
		if err := transaction.QueryRowContext(ctx, `SELECT plan_digest FROM immutable_plans WHERE plan_id=? AND state_revision=? AND recovery_epoch=?`, record.Request.PlanID, record.Request.StateRevision, record.Request.RecoveryEpoch).Scan(&digest); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return newStoreError(generated.ErrorCodePlanStale, "plan", false, nil)
			}
			return err
		}
		if digest != record.Request.PlanDigest {
			return newStoreError(generated.ErrorCodePlanStale, "plan", false, nil)
		}
		_, err := transaction.ExecContext(ctx, `INSERT INTO acknowledgement_requests(acknowledgement_id,plan_id,plan_digest,target_digest,reason_digest,human_id,authority_id,nonce_digest,state_revision,recovery_epoch,expires_at,status,request_bytes,pending_bytes,created_at,decided_at,consumed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'pending',?,?,?,NULL,NULL)`, record.Pending.AcknowledgementID, record.Request.PlanID, record.Request.PlanDigest, record.Request.TargetDigest, record.Request.ReasonDigest, record.Request.HumanID, record.Request.AuthorityID, record.Request.NonceDigest, record.Request.StateRevision, record.Request.RecoveryEpoch, record.Request.ExpiresAt, requestBytes, pendingBytes, record.CreatedAt.Format(time.RFC3339))
		return err
	})
	if err != nil {
		return acknowledgement.Stored{}, false, err
	}
	stored, err := repository.Get(ctx, record.Request.PlanID)
	return stored, result.Created, err
}

func (repository *AcknowledgementRepository) Get(ctx context.Context, planID string) (acknowledgement.Stored, error) {
	if repository == nil || repository.store == nil || planID == "" {
		return acknowledgement.Stored{}, newStoreError(generated.ErrorCodeInputInvalid, "acknowledgement", false, nil)
	}
	var requestBytes, pendingBytes, proofBytes []byte
	var status string
	var consumedAt sql.NullString
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT r.request_bytes,r.pending_bytes,r.status,r.consumed_at,COALESCE(p.canonical_bytes,X'') FROM acknowledgement_requests r LEFT JOIN acknowledgement_proofs p ON p.acknowledgement_id=r.acknowledgement_id WHERE r.plan_id=?`, planID).Scan(&requestBytes, &pendingBytes, &status, &consumedAt, &proofBytes)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return acknowledgement.Stored{}, newStoreError(generated.ErrorCodeResourceNotFound, "acknowledgement", false, nil)
	}
	if err != nil {
		return acknowledgement.Stored{}, err
	}
	var stored acknowledgement.Stored
	if !decodeExact(requestBytes, generated.SchemaIDAcknowledgementRequest, &stored.Request) {
		return acknowledgement.Stored{}, newStoreError(generated.ErrorCodeIntegrityFailure, "acknowledgement-request", false, nil)
	}
	outcomeBytes := pendingBytes
	if status != "pending" {
		outcomeBytes = proofBytes
	}
	if !decodeExact(outcomeBytes, generated.SchemaIDAcknowledgement, &stored.Acknowledgement) || stored.Acknowledgement.Status != status {
		return acknowledgement.Stored{}, newStoreError(generated.ErrorCodeIntegrityFailure, "acknowledgement-proof", false, nil)
	}
	stored.Consumed = consumedAt.Valid
	return stored, nil
}

func (repository *AcknowledgementRepository) Decide(ctx context.Context, record acknowledgement.DecisionRecord) (acknowledgement.Stored, bool, error) {
	expectedAttribution := record.Attribution.AuthenticatedPrincipalID == record.Expected.HumanID
	if record.Outcome.Status == "expired" {
		expectedAttribution = record.Attribution.AuthenticatedPrincipalID == acknowledgement.ExpiryPrincipalID && record.Attribution.AuthenticatedPrincipalMethod == acknowledgement.ExpiryPrincipalMode && record.Attribution.ResponsibleHumanPrincipalID == nil && record.Attribution.Agent == nil
	}
	if repository == nil || repository.store == nil || record.DecidedAt.IsZero() || record.DecidedAt.Location() != time.UTC || !expectedAttribution || !validAcknowledgementDecision(record) {
		return acknowledgement.Stored{}, false, newStoreError(generated.ErrorCodeInputInvalid, "acknowledgement-decision", false, nil)
	}
	expectedBytes, _ := json.Marshal(record.Expected)
	proofBytes, _ := json.Marshal(record.Outcome)
	after := audit.Fingerprint(record.Outcome.ProofDigest)
	eventType := audit.EventType("acknowledgement." + record.Outcome.Status)
	event := audit.EventDraft{Type: eventType, CorrelationID: record.Outcome.AcknowledgementID, Attribution: record.Attribution, Target: audit.Target{Kind: "plan", ID: record.Expected.PlanID}, After: &after}
	key := audit.IntentKey{Scope: "acknowledgement-decision", KeyDigest: audit.Fingerprint(hashText(record.Outcome.ProofDigest)), RequestDigest: audit.Fingerprint(hashBytes(proofBytes))}
	result, err := repository.store.executeAuditIntent(ctx, intentRequest{Expected: &RevisionToken{StateRevision: record.Expected.StateRevision, RecoveryEpoch: record.Expected.RecoveryEpoch}, Idempotency: key, Event: event}, false, func(ctx context.Context, transaction *sql.Tx) error {
		var requestBytes []byte
		var status string
		if err := transaction.QueryRowContext(ctx, `SELECT request_bytes,status FROM acknowledgement_requests WHERE acknowledgement_id=?`, record.Outcome.AcknowledgementID).Scan(&requestBytes, &status); err != nil {
			return err
		}
		if string(requestBytes) != string(expectedBytes) || status != "pending" {
			return newStoreError(generated.ErrorCodePlanStale, "acknowledgement", false, nil)
		}
		if _, err := transaction.ExecContext(ctx, `UPDATE acknowledgement_requests SET status=?,decided_at=? WHERE acknowledgement_id=? AND status='pending'`, record.Outcome.Status, record.DecidedAt.Format(time.RFC3339), record.Outcome.AcknowledgementID); err != nil {
			return err
		}
		_, err := transaction.ExecContext(ctx, `INSERT INTO acknowledgement_proofs(acknowledgement_id,proof_digest,status,canonical_bytes,received_at) VALUES(?,?,?,?,?)`, record.Outcome.AcknowledgementID, record.Outcome.ProofDigest, record.Outcome.Status, proofBytes, record.Outcome.ReceivedAt)
		return err
	})
	if err != nil {
		return acknowledgement.Stored{}, false, err
	}
	stored, err := repository.Get(ctx, record.Expected.PlanID)
	return stored, result.Created, err
}

func (repository *AcknowledgementRepository) Consume(ctx context.Context, planID string, consumedAt time.Time) (acknowledgement.Stored, bool, error) {
	if repository == nil || repository.store == nil || planID == "" || consumedAt.IsZero() || consumedAt.Location() != time.UTC {
		return acknowledgement.Stored{}, false, newStoreError(generated.ErrorCodeInputInvalid, "acknowledgement-consume", false, nil)
	}
	stored, err := repository.Get(ctx, planID)
	if err != nil {
		return acknowledgement.Stored{}, false, err
	}
	if stored.Consumed {
		return stored, false, nil
	}
	after := audit.Fingerprint(stored.Acknowledgement.ProofDigest)
	attribution := audit.Attribution{AuthenticatedPrincipalID: stored.Acknowledgement.HumanID, AuthenticatedPrincipalMethod: "slack-socket-mode"}
	event := audit.EventDraft{Type: "acknowledgement.consumed", CorrelationID: stored.Acknowledgement.AcknowledgementID, Attribution: attribution, Target: audit.Target{Kind: "plan", ID: planID}, After: &after}
	key := audit.IntentKey{Scope: "acknowledgement-consume", KeyDigest: audit.Fingerprint(hashText(stored.Acknowledgement.ProofDigest)), RequestDigest: audit.Fingerprint(hashText(consumedAt.Format(time.RFC3339)))}
	result, err := repository.store.executeAuditIntent(ctx, intentRequest{Expected: &RevisionToken{StateRevision: stored.Request.StateRevision, RecoveryEpoch: stored.Request.RecoveryEpoch}, Idempotency: key, Event: event}, false, func(ctx context.Context, transaction *sql.Tx) error {
		result, err := transaction.ExecContext(ctx, `UPDATE acknowledgement_requests SET consumed_at=? WHERE plan_id=? AND status='approved' AND consumed_at IS NULL`, consumedAt.Format(time.RFC3339), planID)
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil || rows != 1 {
			return newStoreError(generated.ErrorCodePlanStale, "acknowledgement-proof", false, err)
		}
		return nil
	})
	if err != nil {
		return acknowledgement.Stored{}, false, err
	}
	stored, err = repository.Get(ctx, planID)
	return stored, result.Created, err
}

// VerifyRunClaim proves that the acknowledgement has exactly one durable,
// still-queued owner created at the timestamp supplied by the run engine. The
// partial unique index on plan_runs.acknowledgement_id prevents a second owner.
func (repository *AcknowledgementRepository) VerifyRunClaim(ctx context.Context, planID, acknowledgementID string, claimedAt time.Time) error {
	if repository == nil || repository.store == nil || planID == "" || acknowledgementID == "" || claimedAt.IsZero() || claimedAt.Location() != time.UTC {
		return newStoreError(generated.ErrorCodeInputInvalid, "acknowledgement-run-claim", false, nil)
	}
	var count int
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT COUNT(*) FROM plan_runs WHERE plan_id=? AND acknowledgement_id=? AND created_at=? AND status='queued'`, planID, acknowledgementID, claimedAt.Format(time.RFC3339)).Scan(&count)
	})
	if err != nil {
		return err
	}
	if count != 1 {
		return newStoreError(generated.ErrorCodeAuthorizationDenied, "acknowledgement-run-claim", false, nil)
	}
	return nil
}

func (repository *AcknowledgementRepository) RecordDenial(ctx context.Context, record acknowledgement.DenialRecord) error {
	if repository == nil || repository.store == nil || record.TargetKind == "" || record.TargetID == "" || record.CorrelationID == "" || !audit.ValidFingerprint(audit.Fingerprint(record.AttemptDigest)) || record.ReasonCode == "" || record.RejectedAt.IsZero() || record.RejectedAt.Location() != time.UTC {
		return newStoreError(generated.ErrorCodeInputInvalid, "acknowledgement-denial", false, nil)
	}
	after := audit.Fingerprint(record.AttemptDigest)
	event := audit.EventDraft{Type: acknowledgementDenialEventType(record.ReasonCode), CorrelationID: record.CorrelationID, Attribution: record.Attribution, Target: audit.Target{Kind: audit.TargetKind(record.TargetKind), ID: record.TargetID}, After: &after}
	key := audit.IntentKey{Scope: "acknowledgement-denial", KeyDigest: after, RequestDigest: audit.Fingerprint(hashText(record.ReasonCode))}
	_, err := repository.store.executeAuditIntent(ctx, intentRequest{Idempotency: key, Event: event}, false, func(context.Context, *sql.Tx) error { return nil })
	return err
}

func acknowledgementDenialEventType(reason string) audit.EventType {
	switch reason {
	case generated.ErrorCodeInputInvalid:
		return "acknowledgement.input-denied"
	case generated.ErrorCodePlanStale:
		return "acknowledgement.stale-denied"
	case generated.ErrorCodeRecoveryEpochMismatch:
		return "acknowledgement.epoch-denied"
	case generated.ErrorCodeAuthorizationDenied:
		return "acknowledgement.authorization-denied"
	default:
		return "acknowledgement.proof-denied"
	}
}

func validAcknowledgementCreate(record acknowledgement.CreateRecord) bool {
	requestBytes, requestErr := json.Marshal(record.Request)
	pendingBytes, pendingErr := json.Marshal(record.Pending)
	return requestErr == nil && pendingErr == nil && generated.ValidateContractJSON(generated.SchemaIDAcknowledgementRequest, requestBytes, generated.ContractExact) == nil && generated.ValidateContractJSON(generated.SchemaIDAcknowledgement, pendingBytes, generated.ContractExact) == nil && record.Pending.Status == "pending" && sameAcknowledgementBinding(record.Request, record.Pending)
}

func validAcknowledgementDecision(record acknowledgement.DecisionRecord) bool {
	expectedBytes, expectedErr := json.Marshal(record.Expected)
	proofBytes, proofErr := json.Marshal(record.Outcome)
	return expectedErr == nil && proofErr == nil && generated.ValidateContractJSON(generated.SchemaIDAcknowledgementRequest, expectedBytes, generated.ContractExact) == nil && generated.ValidateContractJSON(generated.SchemaIDAcknowledgement, proofBytes, generated.ContractExact) == nil && (record.Outcome.Status == "approved" || record.Outcome.Status == "rejected" || record.Outcome.Status == "expired") && sameAcknowledgementBinding(record.Expected, record.Outcome) && record.Outcome.ReceivedAt == record.DecidedAt.Format(time.RFC3339)
}

func sameAcknowledgementBinding(request generated.AcknowledgementRequest, outcome generated.Acknowledgement) bool {
	return request.PlanID == outcome.PlanID && request.PlanDigest == outcome.PlanDigest && request.TargetDigest == outcome.TargetDigest && request.ReasonDigest == outcome.ReasonDigest && request.HumanID == outcome.HumanID && request.AuthorityID == outcome.AuthorityID && request.NonceDigest == outcome.NonceDigest && request.StateRevision == outcome.StateRevision && request.RecoveryEpoch == outcome.RecoveryEpoch && request.ExpiresAt == outcome.ExpiresAt
}

func decodeExact(raw []byte, schema string, destination any) bool {
	if len(raw) == 0 || generated.ValidateContractJSON(schema, raw, generated.ContractExact) != nil || json.Unmarshal(raw, destination) != nil {
		return false
	}
	reencoded, err := json.Marshal(destination)
	return err == nil && string(reencoded) == string(raw)
}

func hashText(value string) string { return hashBytes([]byte(value)) }

func hashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
