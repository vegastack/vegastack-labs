//go:build linux

package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/store"
)

// VerifyOffsiteRestoredSnapshot inspects a fresh custody-produced restore and
// binds it to the exact durable #114 source manifest. The restored tree is
// never used as authority and contains no credential material.
func VerifyOffsiteRestoredSnapshot(ctx context.Context, target, capturedPath string, manifestBytes []byte, manifestDigest string, inspector store.RestoredSQLiteInspector, ownerUID uint32) (string, error) {
	if target == "" || !filepath.IsAbs(target) || filepath.Clean(target) != target || !filepath.IsAbs(capturedPath) || inspector == nil {
		return "", errors.New("offsite restored snapshot invalid")
	}
	var manifest CreationManifest
	if json.Unmarshal(manifestBytes, &manifest) != nil {
		return "", errors.New("offsite restored manifest invalid")
	}
	canonical, digest, err := CanonicalCreationManifest(manifest)
	if err != nil || digest != manifestDigest || string(canonical) != string(manifestBytes) {
		return "", errors.New("offsite restored manifest mismatch")
	}
	restoredPath := filepath.Join(target, strings.TrimPrefix(filepath.Clean(capturedPath), string(filepath.Separator)))
	contentDigest, err := hashRestoredSQLite(restoredPath, ownerUID)
	if err != nil || contentDigest != manifest.ContentDigest {
		return "", errors.New("offsite restored content mismatch")
	}
	rawCatalog, err := hex.DecodeString(strings.TrimPrefix(manifest.CatalogDigest, "sha256:"))
	if err != nil || len(rawCatalog) != sha256.Size {
		return "", errors.New("offsite restored catalog invalid")
	}
	var catalog [32]byte
	copy(catalog[:], rawCatalog)
	expectation := store.SnapshotExpectation{SchemaVersion: manifest.DatabaseSchemaVersion, Revision: store.RevisionToken{StateRevision: manifest.SourceRevision, RecoveryEpoch: manifest.RecoveryEpoch}, CatalogSHA256: catalog}
	ownerInspector, ok := inspector.(store.RestoredSQLiteOwnerInspector)
	if !ok {
		return "", errors.New("offsite restored owner inspector unavailable")
	}
	inspection, err := ownerInspector.InspectSnapshotOwned(ctx, restoredPath, expectation, ownerUID)
	if err != nil || inspection.IntegrityStatus != store.IntegrityVerified || inspection.Revision != expectation.Revision || inspection.SchemaVersion != expectation.SchemaVersion {
		return "", errors.New("offsite restored sqlite inspection failed")
	}
	proofBody, _ := json.Marshal(struct{ ManifestDigest, ContentDigest, CatalogDigest, DependencyDigest string }{manifestDigest, contentDigest, manifest.CatalogDigest, manifest.DependencyInventoryDigest})
	sum := sha256.Sum256(append([]byte("offsite-isolated-restore-v1\x00"), proofBody...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
