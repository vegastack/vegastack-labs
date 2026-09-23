package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type RecoveredAuthorityBundle struct {
	Plan     generated.Plan
	Readable string
	Request  generated.RestoreRequest
	Binding  generated.RestoreBinding
	Status   string
}

func (store *Store) WriteRecoveredAuthorityBundle(ctx context.Context, bundle RecoveredAuthorityBundle) (string, error) {
	planBytes, requestBytes, bindingBytes, digest, err := validateRecoveredAuthorityBundle(bundle)
	if store == nil || err != nil || bundle.Status != "verification-required" {
		return "", newStoreError(generated.ErrorCodeInputInvalid, "recovery-authority-bundle", false, err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var instance, mode string
	var epoch int64
	if err := tx.QueryRowContext(ctx, `SELECT instance_id,recovery_epoch,authority_mode FROM system_meta WHERE id=1`).Scan(&instance, &epoch, &mode); err != nil || instance != bundle.Binding.NewInstanceID || epoch != bundle.Binding.NextRecoveryEpoch || mode != "recovery-required" {
		return "", newStoreError(generated.ErrorCodeStateConflict, "recovery-authority-bundle", false, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_authority_bundles(plan_id,plan_digest,bundle_digest,plan_bytes,readable_plan,request_bytes,binding_bytes,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, bundle.Plan.PlanID, bundle.Plan.PlanDigest, digest, planBytes, bundle.Readable, requestBytes, bindingBytes, bundle.Status, store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)); err != nil {
		return "", newStoreError(generated.ErrorCodeStateConflict, "recovery-authority-bundle", false, err)
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return digest, nil
}

func (store *Store) RecoveredAuthorityBundle(ctx context.Context, planID string) (RecoveredAuthorityBundle, string, error) {
	var result RecoveredAuthorityBundle
	var planBytes, requestBytes, bindingBytes []byte
	var digest string
	var bundleStatus string
	var journalPlanDigest string
	err := store.Read(ctx, func(tx ReadTx) error {
		if err := tx.queryRow(ctx, `SELECT plan_bytes,readable_plan,request_bytes,binding_bytes,status,bundle_digest FROM recovery_authority_bundles WHERE plan_id=?`, planID).Scan(&planBytes, &result.Readable, &requestBytes, &bindingBytes, &bundleStatus, &digest); err != nil {
			return err
		}
		rows, err := tx.query(ctx, `SELECT transition,plan_digest,binding_bytes FROM recovery_authority_journal WHERE plan_id=? ORDER BY transition`, planID)
		if err != nil {
			return err
		}
		defer rows.Close()
		promoted, verified := 0, 0
		for rows.Next() {
			var transition, planDigest string
			var journalBinding []byte
			if err := rows.Scan(&transition, &planDigest, &journalBinding); err != nil || !bytes.Equal(journalBinding, bindingBytes) || journalPlanDigest != "" && journalPlanDigest != planDigest {
				return errors.New("recovery journal diverged")
			}
			journalPlanDigest = planDigest
			switch transition {
			case "promoted":
				promoted++
			case "verified":
				verified++
			default:
				return errors.New("unexpected recovery transition")
			}
		}
		if err := rows.Err(); err != nil || promoted != 1 || verified > 1 {
			return errors.New("incomplete recovery journal")
		}
		result.Status = "verification-required"
		if verified == 1 {
			result.Status = "verified"
		}
		return nil
	})
	if errors.Is(err, sql.ErrNoRows) {
		return result, "", newStoreError(generated.ErrorCodeResourceNotFound, "recovery-authority-bundle", false, nil)
	}
	if err != nil || json.Unmarshal(planBytes, &result.Plan) != nil || json.Unmarshal(requestBytes, &result.Request) != nil || json.Unmarshal(bindingBytes, &result.Binding) != nil || journalPlanDigest != result.Plan.PlanDigest {
		return RecoveredAuthorityBundle{}, "", newStoreError(generated.ErrorCodeIntegrityFailure, "recovery-authority-bundle", false, err)
	}
	validation := result
	validation.Status = bundleStatus
	_, _, _, computed, validationErr := validateRecoveredAuthorityBundle(validation)
	if validationErr != nil || computed != digest {
		return RecoveredAuthorityBundle{}, "", newStoreError(generated.ErrorCodeIntegrityFailure, "recovery-authority-bundle", false, validationErr)
	}
	return result, digest, nil
}

func validateRecoveredAuthorityBundle(bundle RecoveredAuthorityBundle) ([]byte, []byte, []byte, string, error) {
	planBytes, planErr := json.Marshal(bundle.Plan)
	requestBytes, requestErr := json.Marshal(bundle.Request)
	bindingBytes, bindingErr := json.Marshal(bundle.Binding)
	if planErr != nil || requestErr != nil || bindingErr != nil || generated.ValidateContractJSON(generated.SchemaIDPlan, planBytes, generated.ContractExact) != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreRequest, requestBytes, generated.ContractExact) != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreBinding, bindingBytes, generated.ContractExact) != nil || !validPlanDigests(bundle.Plan, bundle.Readable) || !validRestoreBinding(bundle.Binding) || bundle.Binding.PlanID != bundle.Plan.PlanID || bundle.Binding.PlanDigest != bundle.Plan.PlanDigest || bundle.Binding.HumanAcknowledgementID == "" || bundle.Binding.HumanAcknowledgementID == "pending-human-acknowledgement" || !restoreRequestMatchesBinding(bundle.Request, bundle.Binding) || len(bundle.Plan.Operations) != 1 || bundle.Plan.Operations[0].OperationType != "recovery.restore.cutover" || bundle.Plan.Operations[0].AdapterID != "core.recovery" || bundle.Plan.Operations[0].TargetID != bundle.Binding.TargetIDs[0] {
		return nil, nil, nil, "", errors.New("invalid recovered authority bundle")
	}
	raw, err := json.Marshal(struct {
		Domain  string
		Plan    generated.Plan
		Request generated.RestoreRequest
		Binding generated.RestoreBinding
		Status  string
	}{"vegastack-labs.dev/recovered-authority-bundle/v1", bundle.Plan, bundle.Request, bundle.Binding, bundle.Status})
	if err != nil {
		return nil, nil, nil, "", err
	}
	sum := sha256.Sum256(raw)
	return planBytes, requestBytes, bindingBytes, "sha256:" + hex.EncodeToString(sum[:]), nil
}
