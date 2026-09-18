package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// LookupLifecycleDraft returns only the exact sealed inert binding metadata.
// It does not qualify the draft as an applied version or an executable plan.
func (repository *CredentialRepository) LookupLifecycleDraft(ctx context.Context, declarationID string, revision int64, operationID string) (credentialref.LifecycleBinding, error) {
	var zero credentialref.LifecycleBinding
	if repository == nil || repository.store == nil || revision <= 0 {
		return zero, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-lifecycle-draft")
	}
	for _, id := range []string{declarationID, operationID} {
		if _, err := credentialref.ParseID(id); err != nil {
			return zero, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-lifecycle-draft")
		}
	}
	var raw []byte
	var digest string
	var epoch int64
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT binding_bytes,binding_digest,recovery_epoch FROM credential_lifecycle_bindings WHERE declaration_id=? AND declaration_revision=? AND operation_id=?`, declarationID, revision, operationID).Scan(&raw, &digest, &epoch)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return zero, credentialStoreError(generated.ErrorCodeResourceNotFound, "credential-lifecycle-draft")
	}
	if err != nil {
		return zero, err
	}
	var binding credentialref.LifecycleBinding
	if len(raw) > 4096 || json.Unmarshal(raw, &binding) != nil || binding.OperationID != operationID || binding.RecoveryEpoch != epoch || credentialref.LifecycleManifestDigestOf(binding) != digest || digest == "" {
		return zero, credentialStoreError(generated.ErrorCodeIntegrityFailure, "credential-lifecycle-draft")
	}
	return binding, nil
}
