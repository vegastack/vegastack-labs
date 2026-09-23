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

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func (repository *LocalRetirementRepository) BeginRetirementCustody(ctx context.Context, leaseID, nonceDigest string) error {
	if repository == nil || repository.store == nil || !validRetirementID(leaseID) || !validBackupDigest(nonceDigest) {
		return newStoreError(generated.ErrorCodeInputInvalid, "retirement-custody", false, nil)
	}
	id := "retirement-custody-" + nonceDigest[7:39]
	now := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	return repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_retirement_leases WHERE lease_id=? AND released_at IS NULL`, leaseID).Scan(&n); err != nil || n != 1 {
			return newStoreError(generated.ErrorCodePlanStale, "retirement-custody", false, err)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_retirement_custody_attempts(attempt_id,lease_id,nonce_digest,begun_at) VALUES(?,?,?,?)`, id, leaseID, nonceDigest, now)
		return err
	})
}
func (repository *LocalRetirementRepository) FinishRetirementCustody(ctx context.Context, nonceDigest, outcome string) error {
	if !validBackupDigest(nonceDigest) || (outcome != "succeeded" && outcome != "failed" && outcome != "uncertain") {
		return newStoreError(generated.ErrorCodeInputInvalid, "retirement-custody", false, nil)
	}
	id := "retirement-custody-" + nonceDigest[7:39]
	now := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	return repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_retirement_custody_outcomes(attempt_id,outcome,recorded_at) VALUES(?,?,?)`, id, outcome, now)
		return err
	})
}

type LocalRetirementSettlement struct {
	IntentID, LeaseID, SuccessorInventoryDigest, JournalDigest, SurvivorProofDigest string
	SurvivorPointIDs                                                                []string
	MeasuredReclaimBytes                                                            int64
	RecoveryEpoch                                                                   int64
}

func (repository *LocalRetirementRepository) CommitLocalRetirementSuccess(ctx context.Context, request LocalRetirementSettlement) (string, error) {
	if repository == nil || repository.store == nil || !validRetirementID(request.IntentID) || !validRetirementID(request.LeaseID) || !validBackupDigest(request.SuccessorInventoryDigest) || !validBackupDigest(request.JournalDigest) || !validBackupDigest(request.SurvivorProofDigest) || len(request.SurvivorPointIDs) == 0 || request.MeasuredReclaimBytes < 0 {
		return "", newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-settlement", false, nil)
	}
	ids := append([]string(nil), request.SurvivorPointIDs...)
	sort.Strings(ids)
	canonical, _ := json.Marshal(struct {
		IntentID, InventoryDigest, JournalDigest, ProofDigest string
		Survivors                                             []string
		Reclaimed                                             int64
		Epoch                                                 int64
	}{request.IntentID, request.SuccessorInventoryDigest, request.JournalDigest, request.SurvivorProofDigest, ids, request.MeasuredReclaimBytes, request.RecoveryEpoch})
	sum := sha256.Sum256(canonical)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	generationID := "retirement-generation-" + hex.EncodeToString(sum[:16])
	receiptID := "retirement-receipt-" + hex.EncodeToString(sum[:16])
	now := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	err := repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var repo, class, pred, intentCanonical string
		var state, epoch, survivors int64
		if err := tx.QueryRowContext(ctx, `SELECT i.repository_id,i.repository_class,i.expected_inventory_digest,i.canonical_json,i.state_revision,i.recovery_epoch,i.survivor_count FROM backup_retirement_intents i JOIN backup_retirement_leases l ON l.intent_id=i.intent_id WHERE i.intent_id=? AND l.lease_id=? AND l.released_at IS NULL`, request.IntentID, request.LeaseID).Scan(&repo, &class, &pred, &intentCanonical, &state, &epoch, &survivors); err != nil {
			return err
		}
		if epoch != request.RecoveryEpoch || survivors != int64(len(ids)) {
			return newStoreError(generated.ErrorCodePlanStale, "local-retirement-settlement", false, nil)
		}
		var staged struct {
			Selection retirementSelectionPayload
		}
		if json.Unmarshal([]byte(intentCanonical), &staged) != nil {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-intent", false, nil)
		}
		expectedSurvivors := make([]string, len(staged.Selection.Survivors))
		for index, survivor := range staged.Selection.Survivors {
			expectedSurvivors[index] = survivor.PointID
		}
		sort.Strings(expectedSurvivors)
		if len(expectedSurvivors) != len(ids) {
			return newStoreError(generated.ErrorCodePlanStale, "local-retirement-survivors", false, nil)
		}
		for index := range ids {
			if ids[index] != expectedSurvivors[index] {
				return newStoreError(generated.ErrorCodePlanStale, "local-retirement-survivors", false, nil)
			}
		}
		var bad int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_retirement_mutation_attempts a LEFT JOIN backup_retirement_mutation_outcomes o ON o.mutation_id=a.mutation_id WHERE a.lease_id=? AND (o.mutation_id IS NULL OR o.status IN ('denied','uncertain'))`, request.LeaseID).Scan(&bad); err != nil || bad != 0 {
			return newStoreError(generated.ErrorCodeRecoveryRequired, "local-retirement-settlement", false, err)
		}
		var custodyAttempts, custodySucceeded int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(CASE WHEN o.outcome='succeeded' THEN 1 ELSE 0 END),0)
			FROM backup_retirement_custody_attempts a LEFT JOIN backup_retirement_custody_outcomes o ON o.attempt_id=a.attempt_id WHERE a.lease_id=?`, request.LeaseID).
			Scan(&custodyAttempts, &custodySucceeded); err != nil || custodyAttempts != 1 || custodySucceeded != 1 {
			return newStoreError(generated.ErrorCodeRecoveryRequired, "local-retirement-custody", false, err)
		}
		var prior *string
		var seq int64
		var raw sql.NullString
		_ = tx.QueryRowContext(ctx, `SELECT generation_digest,generation_sequence FROM backup_retirement_successor_generations WHERE repository_class=? AND recovery_epoch=? ORDER BY generation_sequence DESC LIMIT 1`, class, epoch).Scan(&raw, &seq)
		if raw.Valid {
			prior = &raw.String
		}
		seq++
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_retirement_successor_generations(generation_id,intent_id,repository_id,repository_class,recovery_epoch,generation_sequence,parent_generation_digest,generation_digest,predecessor_inventory_digest,successor_inventory_digest,journal_digest,survivor_proof_digest,survivor_count,canonical_json,state_revision,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, generationID, request.IntentID, repo, class, epoch, seq, prior, digest, pred, request.SuccessorInventoryDigest, request.JournalDigest, request.SurvivorProofDigest, len(ids), string(canonical), state, now)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO backup_retirement_receipts(receipt_id,intent_id,lease_id,status,journal_digest,proof_digest,reason_code,recorded_at) VALUES(?,?,?,'verified',?,?,'verified',?)`, receiptID, request.IntentID, request.LeaseID, request.JournalDigest, request.SurvivorProofDigest, now)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE backup_retirement_leases SET released_at=? WHERE lease_id=? AND released_at IS NULL`, now, request.LeaseID)
		if err != nil {
			return err
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return newStoreError(generated.ErrorCodeStateConflict, "local-retirement-release", false, nil)
		}
		return nil
	})
	return digest, err
}

func (repository *LocalRetirementRepository) LocalRetirementVerified(ctx context.Context, intentID, digest string) error {
	var got string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT generation_digest FROM backup_retirement_successor_generations WHERE intent_id=?`, intentID).Scan(&got)
	})
	if errors.Is(err, sql.ErrNoRows) || got != digest {
		return newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-verification", false, nil)
	}
	return err
}

func (repository *LocalRetirementRepository) LocalRetirementJournalDigest(ctx context.Context, leaseID string) (string, error) {
	if repository == nil || repository.store == nil || !validRetirementID(leaseID) {
		return "", newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-journal", false, nil)
	}
	type row struct {
		MutationID               string
		Sequence                 int64
		Kind, Type, Name, Digest string
		Bytes                    int64
		Status, Quarantine       string
	}
	rowsOut := []row{}
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		rows, err := tx.query(ctx, `SELECT a.mutation_id,a.sequence,a.mutation_kind,a.object_type,a.object_name,a.object_digest,a.object_bytes,o.status,COALESCE(o.quarantine_name,'') FROM backup_retirement_mutation_attempts a JOIN backup_retirement_mutation_outcomes o ON o.mutation_id=a.mutation_id WHERE a.lease_id=? ORDER BY a.sequence`, leaseID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r row
			if rows.Scan(&r.MutationID, &r.Sequence, &r.Kind, &r.Type, &r.Name, &r.Digest, &r.Bytes, &r.Status, &r.Quarantine) != nil {
				return errors.New("invalid retirement journal")
			}
			if r.Status == "denied" || r.Status == "uncertain" {
				return newStoreError(generated.ErrorCodeRecoveryRequired, "local-retirement-journal", false, nil)
			}
			rowsOut = append(rowsOut, r)
		}
		return rows.Err()
	})
	if err != nil {
		return "", err
	}
	if len(rowsOut) == 0 {
		return "", newStoreError(generated.ErrorCodeRecoveryRequired, "local-retirement-journal-empty", false, nil)
	}
	canonical, _ := json.Marshal(rowsOut)
	sum := sha256.Sum256(append([]byte("local-retirement-journal-v1\x00"), canonical...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
