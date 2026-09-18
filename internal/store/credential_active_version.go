package store

import (
	"context"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// GetActiveVersion selects the logical current version independently of latest
// staging/revocation events. Exact prior status remains active during overlap;
// only an actually appended, plan-sealed rotation supersedes it logically.
func (repository *CredentialRepository) GetActiveVersion(ctx context.Context, referenceID string, recoveryEpoch int64) (generated.CredentialReference, error) {
	if repository == nil || repository.store == nil || recoveryEpoch < 0 {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-active-version")
	}
	if _, err := credentialref.ParseID(referenceID); err != nil {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-active-version")
	}
	latest := map[string]generated.CredentialReference{}
	type rotation struct {
		planID, operationID, materialVersion, fingerprint string
		stateRevision                                     int64
	}
	var rotations []rotation
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		versionRows, err := tx.query(ctx, `SELECT reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,fingerprint,status,state_revision,recovery_epoch,activated_at,verified_consumers_bytes FROM credential_reference_versions WHERE reference_id=? AND recovery_epoch=? ORDER BY state_revision,version_id`, referenceID, recoveryEpoch)
		if err != nil {
			return err
		}
		for versionRows.Next() {
			var version generated.CredentialReference
			var verified []byte
			if err := versionRows.Scan(&version.ReferenceID, &version.ConsumerID, &version.PurposeID, &version.TargetID, &version.ResolverID, &version.MaterialVersion, &version.Fingerprint, &version.Status, &version.StateRevision, &version.RecoveryEpoch, &version.ActivatedAt, &verified); err != nil {
				versionRows.Close()
				return err
			}
			if json.Unmarshal(verified, &version.VerifiedConsumerIDs) != nil {
				versionRows.Close()
				return credentialStoreError(generated.ErrorCodeIntegrityFailure, "credential-active-version")
			}
			version.Schema, version.SchemaVersion = generated.SchemaIDCredentialReference, "1.1.0"
			latest[version.MaterialVersion] = version
		}
		if err := versionRows.Err(); err != nil {
			versionRows.Close()
			return err
		}
		versionRows.Close()

		rows, err := tx.query(ctx, `SELECT v.plan_id,s.operation_id,v.material_version,v.fingerprint,v.state_revision FROM credential_reference_versions v JOIN plan_run_steps s ON s.run_id=v.run_id AND s.step_id=v.step_id WHERE v.reference_id=? AND v.recovery_epoch=? AND v.status='active' AND s.operation_type='credential.rotate'`, referenceID, recoveryEpoch)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r rotation
			if err := rows.Scan(&r.planID, &r.operationID, &r.materialVersion, &r.fingerprint, &r.stateRevision); err != nil {
				return err
			}
			rotations = append(rotations, r)
		}
		return rows.Err()
	})
	if err != nil {
		return generated.CredentialReference{}, err
	}
	superseded := map[string]bool{}
	for _, rotation := range rotations {
		stored, err := NewPlanRepository(repository.store).GetPlan(ctx, rotation.planID)
		if err != nil {
			return generated.CredentialReference{}, err
		}
		binding, err := repository.GetLifecycleBinding(ctx, stored.Plan, rotation.operationID)
		if err != nil {
			return generated.CredentialReference{}, err
		}
		if binding.Action != credentialref.ActionRotate || binding.PriorMaterialVersion == nil || binding.ReferenceID != referenceID || binding.MaterialVersion != rotation.materialVersion || binding.CiphertextFingerprint != rotation.fingerprint || binding.StateRevision+1 != rotation.stateRevision || binding.RecoveryEpoch != recoveryEpoch {
			return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeIntegrityFailure, "credential-rotation-lineage")
		}
		superseded[*binding.PriorMaterialVersion] = true
	}
	var active generated.CredentialReference
	count := 0
	for versionID, version := range latest {
		if version.Status == "active" && !superseded[versionID] {
			count++
			active = version
		}
	}
	if count == 0 {
		return active, credentialStoreError(generated.ErrorCodeResourceNotFound, "credential-active-version")
	}
	if count != 1 {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeIntegrityFailure, "credential-active-version")
	}
	body, err := json.Marshal(active)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDCredentialReference, body, generated.ContractExact) != nil {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeIntegrityFailure, "credential-active-version")
	}
	return active, nil
}
