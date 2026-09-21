package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
)

// pendingCreationManifest is the store-owned mirror of the v1 wire manifest.
// The store cannot import backup (backup already imports store), so this exact
// shape independently validates the bytes before they become durable authority.
type pendingCreationManifest struct {
	Schema                    string              `json:"schema"`
	SchemaVersion             string              `json:"schemaVersion"`
	PolicyID                  string              `json:"policyId"`
	PolicyDigest              string              `json:"policyDigest"`
	PointID                   string              `json:"pointId"`
	RunID                     string              `json:"runId"`
	StepID                    string              `json:"stepId"`
	RepositoryID              string              `json:"repositoryId"`
	RepositoryClass           string              `json:"repositoryClass"`
	SourceRevision            int64               `json:"sourceRevision"`
	RecoveryEpoch             int64               `json:"recoveryEpoch"`
	ConsistencyHookID         string              `json:"consistencyHookId"`
	ConsistencySuccess        bool                `json:"consistencySuccess"`
	SnapshotID                string              `json:"snapshotId"`
	SnapshotCount             int64               `json:"snapshotCount"`
	ExpectedObjectCount       int64               `json:"expectedObjectCount"`
	ExpectedObjectBytes       int64               `json:"expectedObjectBytes"`
	InventoryDigest           string              `json:"inventoryDigest"`
	ExpectedObjects           []ExpectedObjectRow `json:"expectedObjects"`
	KeyReferenceID            string              `json:"keyReferenceId"`
	ResticDigest              string              `json:"resticDigest"`
	PlatformDigest            string              `json:"platformDigest"`
	SchemaDependencyDigest    string              `json:"schemaDependencyDigest"`
	ConfigDependencyDigest    string              `json:"configDependencyDigest"`
	ImageDependencyDigest     string              `json:"imageDependencyDigest"`
	SignatureDependencyDigest string              `json:"signatureDependencyDigest"`
	StartedAt                 string              `json:"startedAt"`
	CompletedAt               string              `json:"completedAt"`
	FailureCode               string              `json:"failureCode"`
}

func validatePendingManifest(request PendingRecoveryPointRequest) (pendingCreationManifest, error) {
	var manifest pendingCreationManifest
	decoder := json.NewDecoder(bytes.NewReader(request.ManifestJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return manifest, errors.New("trailing manifest data")
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(canonical, request.ManifestJSON) {
		return manifest, errors.New("noncanonical manifest")
	}
	if manifest.Schema != "vegastack-labs.dev/backup-creation-manifest" || manifest.SchemaVersion != "1.0.0" ||
		manifest.PointID != request.PointID || manifest.SnapshotID != request.SnapshotID ||
		manifest.SnapshotCount != request.SnapshotCount || manifest.SourceRevision != request.SourceRevision ||
		manifest.RecoveryEpoch != request.RecoveryEpoch || !manifest.ConsistencySuccess || manifest.FailureCode != "" ||
		manifest.KeyReferenceID == "" || !validBackupDigest(manifest.ResticDigest) || !validBackupDigest(manifest.PlatformDigest) ||
		manifest.ExpectedObjectCount != request.ObjectCount || manifest.ExpectedObjectBytes != request.ObjectBytes ||
		manifest.InventoryDigest != request.InventoryDigest || len(manifest.ExpectedObjects) != len(request.ExpectedObjects) {
		return manifest, errors.New("manifest binding mismatch")
	}
	for _, digest := range []string{manifest.SchemaDependencyDigest, manifest.ConfigDependencyDigest, manifest.ImageDependencyDigest, manifest.SignatureDependencyDigest} {
		if digest != "" && !validBackupDigest(digest) {
			return manifest, errors.New("invalid dependency digest")
		}
	}
	for index, object := range manifest.ExpectedObjects {
		if object != request.ExpectedObjects[index] || !validPendingObject(object) {
			return manifest, errors.New("manifest inventory mismatch")
		}
	}
	if pendingInventoryDigest(request.ExpectedObjects) != request.InventoryDigest {
		return manifest, errors.New("inventory digest mismatch")
	}
	return manifest, nil
}

func validPendingObject(object ExpectedObjectRow) bool {
	if object.Bytes < 0 || !validBackupDigest(object.Digest) {
		return false
	}
	if object.Type == "config" {
		return object.Name == "config"
	}
	switch object.Type {
	case "keys", "data", "index", "snapshots":
	default:
		return false
	}
	if len(object.Name) != 64 {
		return false
	}
	for _, character := range object.Name {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func pendingInventoryDigest(objects []ExpectedObjectRow) string {
	sorted := append([]ExpectedObjectRow(nil), objects...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Type != sorted[j].Type {
			return sorted[i].Type < sorted[j].Type
		}
		return sorted[i].Name < sorted[j].Name
	})
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("backup-expected-inventory-v1"))
	for _, object := range sorted {
		for _, field := range []string{object.Type, object.Name, object.Digest} {
			_, _ = hasher.Write([]byte{0})
			_, _ = hasher.Write([]byte(field))
		}
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(object.Bytes))
		_, _ = hasher.Write(size[:])
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil))
}
