package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// ExpectedObject is one exact expected snapshot object in a pending point's
// inventory. It mirrors the append-only backup_expected_objects row and carries
// no secret material.
type ExpectedObject struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	Digest string `json:"digest"`
}

// ExpectedDependency is one exact policy-declared dependency captured with the
// pending point. A later verifier compares this immutable set with current
// trusted dependency state before qualifying the point.
type ExpectedDependency struct {
	DependencyID string `json:"dependencyId"`
	Kind         string `json:"kind"`
	Digest       string `json:"digest"`
}

// CreationManifest is the canonical secret-free record binding one exact policy,
// point, run and step to the consistency result, repository, expected inventory
// and pinned dependency digests. Field order is also the canonical JSON order.
type CreationManifest struct {
	Schema                    string               `json:"schema"`
	SchemaVersion             string               `json:"schemaVersion"`
	PolicyID                  string               `json:"policyId"`
	PolicyDigest              string               `json:"policyDigest"`
	PointID                   string               `json:"pointId"`
	RunID                     string               `json:"runId"`
	StepID                    string               `json:"stepId"`
	RepositoryID              string               `json:"repositoryId"`
	RepositoryClass           string               `json:"repositoryClass"`
	SourceID                  string               `json:"sourceId"`
	SourceSelectors           []string             `json:"sourceSelectors"`
	SourceRevision            int64                `json:"sourceRevision"`
	RecoveryEpoch             int64                `json:"recoveryEpoch"`
	DatabaseSchemaVersion     uint64               `json:"databaseSchemaVersion"`
	CatalogDigest             string               `json:"catalogDigest"`
	ContentDigest             string               `json:"contentDigest"`
	ConsistencyHookID         string               `json:"consistencyHookId"`
	ConsistencySuccess        bool                 `json:"consistencySuccess"`
	SnapshotID                string               `json:"snapshotId"`
	SnapshotCount             int64                `json:"snapshotCount"`
	ExpectedObjectCount       int64                `json:"expectedObjectCount"`
	ExpectedObjectBytes       int64                `json:"expectedObjectBytes"`
	InventoryDigest           string               `json:"inventoryDigest"`
	ExpectedObjects           []ExpectedObject     `json:"expectedObjects"`
	DependencyInventoryDigest string               `json:"dependencyInventoryDigest"`
	ExpectedDependencies      []ExpectedDependency `json:"expectedDependencies"`
	KeyReferenceID            string               `json:"keyReferenceId"`
	ResticDigest              string               `json:"resticDigest"`
	PlatformDigest            string               `json:"platformDigest"`
	SchemaDependencyDigest    string               `json:"schemaDependencyDigest"`
	ConfigDependencyDigest    string               `json:"configDependencyDigest"`
	ImageDependencyDigest     string               `json:"imageDependencyDigest"`
	SignatureDependencyDigest string               `json:"signatureDependencyDigest"`
	StartedAt                 string               `json:"startedAt"`
	CompletedAt               string               `json:"completedAt"`
	FailureCode               string               `json:"failureCode"`
}

// CreationManifestSchema/Version identify the canonical creation manifest.
const (
	CreationManifestSchema  = "vegastack-labs.dev/backup-creation-manifest"
	CreationManifestVersion = "1.2.0"
)

var expectedObjectTypes = map[string]struct{}{
	"config": {}, "keys": {}, "data": {}, "index": {}, "snapshots": {},
}

// ExpectedDependencyInventoryDigest binds the complete typed dependency set,
// including multiple dependencies of the same kind, without trusting order.
func ExpectedDependencyInventoryDigest(dependencies []ExpectedDependency) string {
	sorted := append([]ExpectedDependency(nil), dependencies...)
	sort.Slice(sorted, func(left, right int) bool {
		if sorted[left].Kind != sorted[right].Kind {
			return sorted[left].Kind < sorted[right].Kind
		}
		return sorted[left].DependencyID < sorted[right].DependencyID
	})
	hasher := sha256.New()
	hasher.Write([]byte("backup-expected-dependencies-v1"))
	for _, dependency := range sorted {
		for _, value := range []string{dependency.Kind, dependency.DependencyID, dependency.Digest} {
			hasher.Write([]byte{0})
			hasher.Write([]byte(value))
		}
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil))
}

// ExpectedInventoryDigest returns the SHA-256 over the canonical, sorted expected
// inventory. Two inventories with the same objects (in any order) share a digest,
// and any missing, extra or altered object changes it.
func ExpectedInventoryDigest(objects []ExpectedObject) string {
	sorted := append([]ExpectedObject(nil), objects...)
	sort.Slice(sorted, func(left, right int) bool {
		if sorted[left].Type != sorted[right].Type {
			return sorted[left].Type < sorted[right].Type
		}
		return sorted[left].Name < sorted[right].Name
	})
	hasher := sha256.New()
	hasher.Write([]byte("backup-expected-inventory-v1"))
	for _, object := range sorted {
		hasher.Write([]byte{0})
		hasher.Write([]byte(object.Type))
		hasher.Write([]byte{0})
		hasher.Write([]byte(object.Name))
		hasher.Write([]byte{0})
		hasher.Write([]byte(object.Digest))
		hasher.Write([]byte{0})
		hasher.Write(int64Bytes(object.Bytes))
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil))
}

func int64Bytes(value int64) []byte {
	var buffer [8]byte
	unsigned := uint64(value)
	for index := 7; index >= 0; index-- {
		buffer[index] = byte(unsigned)
		unsigned >>= 8
	}
	return buffer[:]
}

// CanonicalCreationManifest validates the manifest's internal consistency and
// returns its canonical bytes and SHA-256 digest. It rejects any manifest whose
// declared object count, byte total or inventory digest does not exactly match
// its listed expected objects, or that omits a required binding.
func CanonicalCreationManifest(manifest CreationManifest) ([]byte, string, error) {
	invalid := func() ([]byte, string, error) {
		return nil, "", failure.New(generated.ErrorCodeIntegrityFailure, "backup-creation-manifest", false)
	}
	if manifest.Schema != CreationManifestSchema || manifest.SchemaVersion != CreationManifestVersion {
		return invalid()
	}
	for _, id := range []string{manifest.PolicyID, manifest.PointID, manifest.RunID, manifest.StepID, manifest.RepositoryID, manifest.SourceID, manifest.SnapshotID, manifest.KeyReferenceID, manifest.ConsistencyHookID} {
		if id == "" {
			return invalid()
		}
	}
	if manifest.RepositoryClass != "standard" && manifest.RepositoryClass != "critical" {
		return invalid()
	}
	for _, digest := range []string{manifest.PolicyDigest, manifest.InventoryDigest, manifest.DependencyInventoryDigest, manifest.ResticDigest, manifest.PlatformDigest, manifest.CatalogDigest, manifest.ContentDigest} {
		if !validBackupManifestDigest(digest) {
			return invalid()
		}
	}
	if !manifest.ConsistencySuccess || manifest.SnapshotCount < 1 || manifest.FailureCode != "" || manifest.DatabaseSchemaVersion == 0 {
		return invalid()
	}
	var total int64
	configCount, keyCount, snapshotCount := 0, 0, 0
	for _, object := range manifest.ExpectedObjects {
		if _, ok := expectedObjectTypes[object.Type]; !ok || object.Name == "" || object.Bytes < 0 || !validBackupManifestDigest(object.Digest) {
			return invalid()
		}
		if object.Type == "config" {
			if object.Name != "config" {
				return invalid()
			}
			configCount++
		} else if !validObjectName(object.Name) {
			return invalid()
		}
		if object.Type == "keys" {
			keyCount++
		}
		if object.Type == "snapshots" && object.Name == manifest.SnapshotID {
			snapshotCount++
		}
		total += object.Bytes
	}
	if configCount != 1 || keyCount < 1 || snapshotCount != 1 {
		return invalid()
	}
	if manifest.ExpectedObjectCount != int64(len(manifest.ExpectedObjects)) || len(manifest.ExpectedObjects) == 0 {
		return invalid()
	}
	if manifest.ExpectedObjectBytes != total {
		return invalid()
	}
	if manifest.InventoryDigest != ExpectedInventoryDigest(manifest.ExpectedObjects) {
		return invalid()
	}
	if len(manifest.SourceSelectors) == 0 || manifest.ExpectedDependencies == nil || manifest.DependencyInventoryDigest != ExpectedDependencyInventoryDigest(manifest.ExpectedDependencies) {
		return invalid()
	}
	for _, selector := range manifest.SourceSelectors {
		if selector == "" {
			return invalid()
		}
	}
	seenDependencies := map[string]bool{}
	for _, dependency := range manifest.ExpectedDependencies {
		if dependency.DependencyID == "" || seenDependencies[dependency.DependencyID] || !validBackupManifestDigest(dependency.Digest) {
			return invalid()
		}
		seenDependencies[dependency.DependencyID] = true
		switch dependency.Kind {
		case "binary", "schema", "config", "image", "signature":
		default:
			return invalid()
		}
	}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return invalid()
	}
	sum := sha256.Sum256(canonical)
	return canonical, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func validBackupManifestDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range strings.TrimPrefix(value, "sha256:") {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}
