package store

import (
	"context"
	"slices"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// ReadNativeLoadedReceipt reads only the currently active, exact consumer's
// actual invocation proof. Historical rows lacking proof remain unqualified.
func (repository *CredentialRepository) ReadNativeLoadedReceipt(ctx context.Context, b credentialref.StepBinding) (credentialref.NativeLoadedReceipt, error) {
	deny := func() (credentialref.NativeLoadedReceipt, error) {
		return credentialref.NativeLoadedReceipt{}, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "native-loaded-receipt")
	}
	if repository == nil || repository.store == nil || !credentialref.ValidBinding(b) || b.ResolverID != "native-systemd" {
		return deny()
	}
	active, err := repository.GetActiveVersion(ctx, b.ReferenceID, b.RecoveryEpoch)
	if err != nil || active.Status != "active" || active.MaterialVersion != b.MaterialVersion || active.ConsumerID != b.ConsumerID || active.PurposeID != b.PurposeID || active.TargetID != b.TargetID || active.ResolverID != b.ResolverID || active.StateRevision > b.StateRevision || !slices.Contains(active.VerifiedConsumerIDs, b.ConsumerID) {
		return deny()
	}
	var raw []byte
	var planDigest, runID, stepID string
	err = repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT c.native_receipt_bytes,v.plan_digest,v.run_id,v.step_id FROM credential_consumer_verifications c JOIN credential_reference_versions v ON v.version_id=c.version_id JOIN system_meta m ON m.id=1 WHERE c.reference_id=? AND c.consumer_id=? AND c.material_version=? AND c.recovery_epoch=? AND c.result='verified' AND c.restart_observed=1 AND c.native_receipt_bytes IS NOT NULL AND v.status='active' AND v.state_revision=? AND v.fingerprint=? AND m.recovery_epoch=c.recovery_epoch AND v.state_revision=(SELECT MAX(n.state_revision) FROM credential_reference_versions n WHERE n.reference_id=v.reference_id AND n.material_version=v.material_version)`, b.ReferenceID, b.ConsumerID, b.MaterialVersion, b.RecoveryEpoch, active.StateRevision, active.Fingerprint).Scan(&raw, &planDigest, &runID, &stepID)
	})
	if err != nil {
		return deny()
	}
	r, err := credentialref.DecodeNativeLoadedReceipt(raw)
	if err != nil || r.PlanDigest != planDigest || r.RunID != runID || r.StepID != stepID || r.ConsumerID != b.ConsumerID || r.Binding.ReferenceID != b.ReferenceID || r.Binding.MaterialVersion != b.MaterialVersion || r.Binding.TargetID != b.TargetID || r.Binding.RecoveryEpoch != b.RecoveryEpoch || r.Binding.CiphertextFingerprint != active.Fingerprint {
		return deny()
	}
	return r, nil
}
