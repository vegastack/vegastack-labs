package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type CheckpointCreateRequest struct {
	Checkpoint    generated.AuditCheckpoint
	ExactPath     string
	Expected      RevisionToken
	KeyDigest     audit.Fingerprint
	RequestDigest audit.Fingerprint
	Attribution   audit.Attribution
}

type CheckpointSignatureRequest struct {
	CheckpointID, PublicKeyID, ExactPath string
	SignatureDigest, PayloadDigest       audit.Fingerprint
	EncryptedPayload                     []byte
	At                                   time.Time
	KeyDigest, RequestDigest             audit.Fingerprint
	Attribution                          audit.Attribution
}

type CheckpointExportRequest struct {
	CheckpointID             string
	ReceiptDigest            audit.Fingerprint
	At                       time.Time
	KeyDigest, RequestDigest audit.Fingerprint
	Attribution              audit.Attribution
}

type CheckpointSettleRequest struct {
	CheckpointID             string
	IndependentDigest        audit.Fingerprint
	At                       time.Time
	KeyDigest, RequestDigest audit.Fingerprint
	Attribution              audit.Attribution
}

func (store *Store) CreatePendingCheckpoint(ctx context.Context, request CheckpointCreateRequest) (generated.AuditCheckpoint, error) {
	checkpoint := request.Checkpoint
	raw, err := json.Marshal(checkpoint)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDAuditCheckpoint, raw, generated.ContractExact) != nil || checkpoint.Status != "pending" || checkpoint.SignatureDigest != nil || checkpoint.ExportReceiptDigest != nil || checkpoint.IndependentReadDigest != nil || request.ExactPath == "" || !audit.ValidFingerprint(audit.Fingerprint(checkpoint.ChainDigest)) {
		return generated.AuditCheckpoint{}, newStoreError("INPUT_INVALID", "audit-checkpoint", false, err)
	}
	after := audit.Fingerprint(checkpoint.ChainDigest)
	event := audit.EventDraft{Type: "audit.checkpoint-pending", CorrelationID: checkpoint.CheckpointID, Attribution: request.Attribution, Target: audit.Target{Kind: "audit-checkpoint", ID: checkpoint.CheckpointID}, After: &after}
	_, err = store.writeIntent(ctx, intentRequest{Expected: &request.Expected, Idempotency: audit.IntentKey{Scope: "audit-checkpoint-create", KeyDigest: request.KeyDigest, RequestDigest: request.RequestDigest}, Event: event}, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_checkpoints(checkpoint_id,schema_version,instance_id,recovery_epoch,first_event_id,last_event_id,first_segment_sequence,last_segment_sequence,chain_digest,signer_reference_id,signer_material_version,signature_digest,public_key_id,export_namespace,export_receipt_digest,independent_read_digest,status,reason_code,pre_anchor,canonical_bytes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,?,NULL,NULL,'pending',?,?,?, ?,?)`, checkpoint.CheckpointID, checkpoint.SchemaVersion, checkpoint.InstanceID, checkpoint.RecoveryEpoch, checkpoint.FirstEventID, checkpoint.LastEventID, checkpoint.FirstSegmentSequence, checkpoint.LastSegmentSequence, checkpoint.ChainDigest, checkpoint.SignerReferenceID, checkpoint.SignerMaterialVersion, request.ExactPath, checkpoint.ReasonCode, checkpoint.PreAnchor, raw, store.config.Clock().UTC().Format(time.RFC3339), store.config.Clock().UTC().Format(time.RFC3339))
		return err
	})
	if err != nil {
		return generated.AuditCheckpoint{}, err
	}
	return store.GetAuditCheckpoint(ctx, checkpoint.CheckpointID)
}

func (store *Store) GetAuditCheckpoint(ctx context.Context, checkpointID string) (generated.AuditCheckpoint, error) {
	if checkpointID == "" {
		return generated.AuditCheckpoint{}, newStoreError("INPUT_INVALID", "audit-checkpoint", false, nil)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyForRead(ctx); err != nil {
		return generated.AuditCheckpoint{}, err
	}
	return scanAuditCheckpoint(store.conn.QueryRowContext(ctx, `SELECT canonical_bytes FROM audit_checkpoints WHERE checkpoint_id=?`, checkpointID))
}

func (store *Store) ListAuditCheckpoints(ctx context.Context) ([]generated.AuditCheckpoint, error) {
	return store.ListAuditCheckpointsPage(ctx, "", 100)
}

func (store *Store) ListAuditCheckpointsPage(ctx context.Context, afterID string, limit int) ([]generated.AuditCheckpoint, error) {
	return store.listAuditCheckpointsPage(ctx, authorization.ReadScope{}, RevisionToken{}, afterID, limit, false)
}

func (store *Store) ListAuditCheckpointsPageScoped(ctx context.Context, scope authorization.ReadScope, snapshot RevisionToken, afterID string, limit int) ([]generated.AuditCheckpoint, error) {
	return store.listAuditCheckpointsPage(ctx, scope, snapshot, afterID, limit, true)
}

func (store *Store) listAuditCheckpointsPage(ctx context.Context, scope authorization.ReadScope, snapshot RevisionToken, afterID string, limit int, scoped bool) ([]generated.AuditCheckpoint, error) {
	if limit < 1 || limit > 101 {
		return nil, newStoreError(generated.ErrorCodeInputInvalid, "audit-checkpoint-page", false, nil)
	}
	var result []generated.AuditCheckpoint
	err := store.Read(ctx, func(tx ReadTx) error {
		if scoped {
			if err := verifyExactReadSnapshot(ctx, tx, scope, snapshot); err != nil {
				return err
			}
		}
		query := `SELECT c.canonical_bytes FROM audit_checkpoints c WHERE c.checkpoint_id>? ORDER BY c.checkpoint_id LIMIT ?`
		args := []any{afterID, limit}
		if scoped {
			query = `SELECT c.canonical_bytes FROM audit_checkpoints c JOIN read_grants g ON g.resource_id=c.checkpoint_id AND g.principal_id=? AND g.capability=? AND g.resource_kind=? AND g.grant_revision=? AND g.status='active' WHERE c.checkpoint_id>? ORDER BY c.checkpoint_id LIMIT ?`
			args = []any{scope.PrincipalID, scope.Capability, scope.ResourceKind, scope.GrantRevision, afterID, limit}
		}
		rows, err := tx.query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			checkpoint, err := scanAuditCheckpoint(rows)
			if err != nil {
				return err
			}
			result = append(result, checkpoint)
		}
		return rows.Err()
	})
	return result, err
}

func (store *Store) RecordCheckpointSignature(ctx context.Context, request CheckpointSignatureRequest) (generated.AuditCheckpoint, error) {
	if request.CheckpointID == "" || request.PublicKeyID == "" || request.ExactPath == "" || !audit.ValidFingerprint(request.SignatureDigest) || !audit.ValidFingerprint(request.PayloadDigest) || len(request.EncryptedPayload) == 0 || request.At.IsZero() {
		return generated.AuditCheckpoint{}, newStoreError("INPUT_INVALID", "audit-checkpoint-signature", false, nil)
	}
	return store.transitionCheckpoint(ctx, request.CheckpointID, "pending", "signed", request.At, request.KeyDigest, request.RequestDigest, request.Attribution, func(checkpoint *generated.AuditCheckpoint, tx *sql.Tx) error {
		signature, key := string(request.SignatureDigest), request.PublicKeyID
		checkpoint.SignatureDigest, checkpoint.PublicKeyID, checkpoint.Status, checkpoint.ReasonCode = &signature, &key, "signed", "signature-created"
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_checkpoint_outbox(checkpoint_id,exact_path,encrypted_payload,payload_digest,status,attempt_count,last_error_code,next_attempt_at,updated_at) VALUES(?,?,?,?, 'pending',0,NULL,NULL,?)`, checkpoint.CheckpointID, request.ExactPath, request.EncryptedPayload, request.PayloadDigest, request.At.UTC().Format(time.RFC3339))
		return err
	})
}

func (store *Store) RecordCheckpointExport(ctx context.Context, request CheckpointExportRequest) (generated.AuditCheckpoint, error) {
	if request.CheckpointID == "" || !audit.ValidFingerprint(request.ReceiptDigest) || request.At.IsZero() {
		return generated.AuditCheckpoint{}, newStoreError("INPUT_INVALID", "audit-checkpoint-export", false, nil)
	}
	return store.transitionCheckpoint(ctx, request.CheckpointID, "signed", "export-pending", request.At, request.KeyDigest, request.RequestDigest, request.Attribution, func(checkpoint *generated.AuditCheckpoint, tx *sql.Tx) error {
		receipt := string(request.ReceiptDigest)
		checkpoint.ExportReceiptDigest, checkpoint.Status, checkpoint.ReasonCode = &receipt, "export-pending", "independent-confirmation-required"
		_, err := tx.ExecContext(ctx, `UPDATE audit_checkpoint_outbox SET status='written',attempt_count=attempt_count+1,updated_at=? WHERE checkpoint_id=? AND status IN ('pending','retry-wait','written')`, request.At.UTC().Format(time.RFC3339), request.CheckpointID)
		return err
	})
}

func (store *Store) SettleCheckpoint(ctx context.Context, request CheckpointSettleRequest) (generated.AuditCheckpoint, error) {
	if request.CheckpointID == "" || !audit.ValidFingerprint(request.IndependentDigest) || request.At.IsZero() {
		return generated.AuditCheckpoint{}, newStoreError("INPUT_INVALID", "audit-checkpoint-settle", false, nil)
	}
	return store.transitionCheckpoint(ctx, request.CheckpointID, "export-pending", "anchored", request.At, request.KeyDigest, request.RequestDigest, request.Attribution, func(checkpoint *generated.AuditCheckpoint, tx *sql.Tx) error {
		independent, verified := string(request.IndependentDigest), request.At.UTC().Truncate(time.Second).Format(time.RFC3339)
		checkpoint.IndependentReadDigest, checkpoint.IndependentCopyDigest = &independent, &independent
		checkpoint.Status, checkpoint.ReasonCode, checkpoint.SourceKind, checkpoint.ProofClass = "anchored", "independent-match", "independent", "live"
		checkpoint.VerifiedAt, checkpoint.VerificationStatus = &verified, "verified"
		_, err := tx.ExecContext(ctx, `UPDATE audit_checkpoint_outbox SET status='confirmed',updated_at=? WHERE checkpoint_id=? AND status='written'`, request.At.UTC().Format(time.RFC3339), request.CheckpointID)
		return err
	})
}

func (store *Store) CheckpointExportPayload(ctx context.Context, checkpointID string) (string, []byte, audit.Fingerprint, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyForRead(ctx); err != nil {
		return "", nil, "", err
	}
	var path string
	var payload []byte
	var digest audit.Fingerprint
	if err := store.conn.QueryRowContext(ctx, `SELECT exact_path,encrypted_payload,payload_digest FROM audit_checkpoint_outbox WHERE checkpoint_id=?`, checkpointID).Scan(&path, &payload, &digest); err != nil {
		return "", nil, "", store.transactionError(ctx, err)
	}
	return path, payload, digest, nil
}

func (store *Store) transitionCheckpoint(ctx context.Context, checkpointID, from, to string, at time.Time, key, requestDigest audit.Fingerprint, attribution audit.Attribution, mutate func(*generated.AuditCheckpoint, *sql.Tx) error) (generated.AuditCheckpoint, error) {
	event := audit.EventDraft{Type: audit.EventType("audit.checkpoint-" + to), CorrelationID: checkpointID, Attribution: attribution, Target: audit.Target{Kind: "audit-checkpoint", ID: checkpointID}}
	_, err := store.executeAuditIntent(ctx, intentRequest{Idempotency: audit.IntentKey{Scope: "audit-checkpoint-" + to, KeyDigest: key, RequestDigest: requestDigest}, Event: event}, false, func(ctx context.Context, tx *sql.Tx) error {
		checkpoint, err := scanAuditCheckpoint(tx.QueryRowContext(ctx, `SELECT canonical_bytes FROM audit_checkpoints WHERE checkpoint_id=? AND status=?`, checkpointID, from))
		if err != nil {
			return err
		}
		if err := mutate(&checkpoint, tx); err != nil {
			return err
		}
		raw, err := json.Marshal(checkpoint)
		if err != nil || generated.ValidateContractJSON(generated.SchemaIDAuditCheckpoint, raw, generated.ContractExact) != nil {
			return errors.New("invalid checkpoint transition")
		}
		result, err := tx.ExecContext(ctx, `UPDATE audit_checkpoints SET signature_digest=?,public_key_id=?,export_receipt_digest=?,independent_read_digest=?,status=?,reason_code=?,canonical_bytes=?,updated_at=? WHERE checkpoint_id=? AND status=?`, checkpoint.SignatureDigest, checkpoint.PublicKeyID, checkpoint.ExportReceiptDigest, checkpoint.IndependentReadDigest, checkpoint.Status, checkpoint.ReasonCode, raw, at.UTC().Format(time.RFC3339), checkpointID, from)
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil || rows != 1 {
			return errors.New("checkpoint transition lost compare")
		}
		return nil
	})
	if err != nil {
		return generated.AuditCheckpoint{}, err
	}
	return store.GetAuditCheckpoint(ctx, checkpointID)
}

func scanAuditCheckpoint(row rowScanner) (generated.AuditCheckpoint, error) {
	var raw []byte
	if err := row.Scan(&raw); err != nil {
		return generated.AuditCheckpoint{}, err
	}
	var checkpoint generated.AuditCheckpoint
	if err := json.Unmarshal(raw, &checkpoint); err != nil || generated.ValidateContractJSON(generated.SchemaIDAuditCheckpoint, raw, generated.ContractExact) != nil {
		return generated.AuditCheckpoint{}, errors.New("invalid persisted checkpoint")
	}
	return checkpoint, nil
}
