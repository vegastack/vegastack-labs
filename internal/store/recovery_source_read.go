package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// LocalRecoverySource is the exact immutable point and live verification named
// by the current local-last-good CAS row. It contains public identities only;
// repository access remains behind the backup custody adapter.
type LocalRecoverySource struct {
	Verification          LocalVerificationReceipt
	Point                 PendingRecoveryPoint
	SnapshotID            string
	DatabaseSchemaVersion uint64
	CatalogDigest         string
	DependencyDigest      string
	KeyReferenceID        string
	CreatedAt             time.Time
	VerifiedAt            time.Time
	FullReadAt            time.Time
	FunctionalRestoredAt  time.Time
}

// CurrentLocalRecoverySource resolves last-good and all of its immutable proof
// in one read transaction. It deliberately does not reuse GetPendingRecoveryPoint:
// that reader is restricted to the pre-verification fixture state.
func (repository *BackupRepository) CurrentLocalRecoverySource(ctx context.Context, class string) (LocalRecoverySource, error) {
	var source LocalRecoverySource
	if repository == nil || repository.store == nil || (class != "standard" && class != "critical") {
		return source, backupStoreError(generated.ErrorCodeInputInvalid, "restore-local-source")
	}
	var manifestJSON, createdText, verifiedText, fullText, restoredText, policyJSON string
	var snapshotCount, objectCount, objectBytes int64
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		row := tx.queryRow(ctx, `SELECT
			v.verification_id,v.proof_digest,v.point_id,p.repository_class,v.status,v.proof_class,v.manifest_digest,v.inventory_digest,v.state_revision,v.recovery_epoch,
			p.job_id,p.policy_id,p.policy_digest,p.repository_id,p.snapshot_id,p.snapshot_count,p.object_count,p.object_bytes,p.content_digest,p.manifest_json,p.source_revision,p.created_at,
			v.catalog_digest,v.dependency_digest,v.key_reference_id,v.created_at,v.full_read_at,v.functional_restored_at,d.canonical_json
		FROM backup_local_last_good g
		JOIN backup_local_verifications v ON v.verification_id=g.verification_id AND v.point_id=g.point_id AND v.state_revision=g.state_revision AND v.recovery_epoch=g.recovery_epoch
		JOIN recovery_points p ON p.point_id=g.point_id AND p.repository_class=g.repository_class AND p.manifest_digest=v.manifest_digest AND p.inventory_digest=v.inventory_digest AND p.content_digest=v.content_digest
		JOIN backup_policy_drafts d ON d.policy_digest=p.policy_digest AND d.recovery_epoch=p.recovery_epoch
		JOIN system_meta m ON m.id=1 AND m.state_revision=g.state_revision AND m.recovery_epoch=g.recovery_epoch
		WHERE g.repository_class=? AND v.status='local-verified' AND v.proof_class='live' AND p.source_kind='local' AND p.proof_class='fixture' AND p.verification_status='pending' AND p.verified_at IS NULL`, class)
		if err := row.Scan(
			&source.Verification.VerificationID, &source.Verification.ProofDigest, &source.Verification.PointID, &source.Verification.RepositoryClass,
			&source.Verification.Status, &source.Verification.ProofClass, &source.Verification.ManifestDigest, &source.Verification.InventoryDigest,
			&source.Verification.StateRevision, &source.Verification.RecoveryEpoch,
			&source.Point.JobID, &source.Point.PolicyID, &source.Point.PolicyDigest, &source.Point.RepositoryID, &source.SnapshotID,
			&snapshotCount, &objectCount, &objectBytes, &source.Point.ContentDigest, &manifestJSON, &source.Point.SourceRevision, &createdText,
			&source.CatalogDigest, &source.DependencyDigest, &source.KeyReferenceID, &verifiedText, &fullText, &restoredText, &policyJSON); err != nil {
			return err
		}
		source.Point.PointID = source.Verification.PointID
		source.Point.RepositoryClass = source.Verification.RepositoryClass
		source.Point.ManifestDigest = source.Verification.ManifestDigest
		source.Point.InventoryDigest = source.Verification.InventoryDigest
		source.Point.RecoveryEpoch = source.Verification.RecoveryEpoch
		source.Point.ManifestJSON = []byte(manifestJSON)

		rows, err := tx.query(ctx, `SELECT object_type,object_name,object_bytes,object_digest FROM backup_expected_objects WHERE point_id=? ORDER BY object_name`, source.Point.PointID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var object ExpectedObjectRow
			if err := rows.Scan(&object.Type, &object.Name, &object.Bytes, &object.Digest); err != nil {
				_ = rows.Close()
				return err
			}
			source.Point.ExpectedObjects = append(source.Point.ExpectedObjects, object)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}

		rows, err = tx.query(ctx, `SELECT dependency_id,dependency_kind,dependency_digest,source_kind,point_id,policy_digest,source_id,artifact_id,bundle_digest,trusted_root_reference_id,trust_root_digest,signer_identity,signer_issuer,source_revision,state_revision,recovery_epoch FROM backup_dependency_trust_evidence WHERE verification_id=? ORDER BY rowid`, source.Verification.VerificationID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var proof BackupDependencyTrustEvidence
			var artifactID, bundleDigest, rootID, rootDigest, identity, issuer sql.NullString
			if err := rows.Scan(&proof.DependencyID, &proof.Kind, &proof.Digest, &proof.SourceKind, &proof.PointID, &proof.PolicyDigest, &proof.SourceID, &artifactID, &bundleDigest, &rootID, &rootDigest, &identity, &issuer, &proof.SourceRevision, &proof.StateRevision, &proof.RecoveryEpoch); err != nil {
				_ = rows.Close()
				return err
			}
			proof.ArtifactID, proof.BundleDigest, proof.TrustedRootReferenceID, proof.TrustRootDigest, proof.SignerIdentity, proof.SignerIssuer = nullTrust(artifactID), nullTrust(bundleDigest), nullTrust(rootID), nullTrust(rootDigest), nullTrust(identity), nullTrust(issuer)
			source.Verification.DependencyTrust = append(source.Verification.DependencyTrust, proof)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		return rows.Close()
	})
	if errors.Is(err, sql.ErrNoRows) {
		return source, backupStoreError(generated.ErrorCodePrerequisiteBlocked, "restore-local-source")
	}
	if err != nil {
		return source, err
	}

	parsed := []*time.Time{&source.CreatedAt, &source.VerifiedAt, &source.FullReadAt, &source.FunctionalRestoredAt}
	for index, text := range []string{createdText, verifiedText, fullText, restoredText} {
		value, parseErr := time.Parse(time.RFC3339, text)
		if parseErr != nil {
			return LocalRecoverySource{}, backupStoreError(generated.ErrorCodeIntegrityFailure, "restore-local-source")
		}
		*parsed[index] = value
	}
	manifestSum := sha256.Sum256(source.Point.ManifestJSON)
	if "sha256:"+hex.EncodeToString(manifestSum[:]) != source.Point.ManifestDigest {
		return LocalRecoverySource{}, backupStoreError(generated.ErrorCodeIntegrityFailure, "restore-local-source")
	}
	request := PendingRecoveryPointRequest{PointID: source.Point.PointID, SnapshotID: source.SnapshotID, SnapshotCount: snapshotCount, ObjectCount: objectCount, ObjectBytes: objectBytes,
		ContentDigest: source.Point.ContentDigest, ManifestDigest: source.Point.ManifestDigest, ManifestJSON: source.Point.ManifestJSON, InventoryDigest: source.Point.InventoryDigest,
		SourceRevision: source.Point.SourceRevision, RecoveryEpoch: source.Point.RecoveryEpoch, SourceKind: "local", ProofClass: "fixture", ExpectedObjects: source.Point.ExpectedObjects}
	manifest, validationErr := validatePendingManifest(request)
	if validationErr != nil || manifest.CatalogDigest != source.CatalogDigest || manifest.DependencyInventoryDigest != source.DependencyDigest || manifest.KeyReferenceID != source.KeyReferenceID ||
		!exactStoredDependencyTrust(manifest.ExpectedDependencies, source.Verification.DependencyTrust, source.Point.PointID, source.Point.PolicyDigest, source.Verification.StateRevision, source.Verification.RecoveryEpoch) {
		return LocalRecoverySource{}, backupStoreError(generated.ErrorCodeIntegrityFailure, "restore-local-source")
	}
	source.DatabaseSchemaVersion = manifest.DatabaseSchemaVersion
	var policy generated.BackupPolicy
	if json.Unmarshal([]byte(policyJSON), &policy) != nil || policy.SchemaVersion != "1.2.0" || policy.FullPayloadIntervalHours < 1 || policy.FunctionalTestIntervalHours < 1 {
		return LocalRecoverySource{}, backupStoreError(generated.ErrorCodeIntegrityFailure, "restore-local-source")
	}
	now := repository.store.config.Clock().UTC()
	if !now.Before(source.FullReadAt.Add(time.Duration(policy.FullPayloadIntervalHours)*time.Hour)) || !now.Before(source.FunctionalRestoredAt.Add(time.Duration(policy.FunctionalTestIntervalHours)*time.Hour)) {
		return LocalRecoverySource{}, backupStoreError(generated.ErrorCodePrerequisiteBlocked, "restore-local-source-cadence")
	}
	return source, nil
}
