//go:build linux

package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalVerifierRejectsMissingExpectedSnapshotDespiteGreenMetadata(t *testing.T) {
	writer, client, done := newRESTFixture(t)
	defer done()
	if code := restDo(t, client, http.MethodPost, "/repo-a/?create=true", nil); code != http.StatusOK { t.Fatalf("repository layout = %d", code) }
	manifest := validCreationManifest(t)
	for index := range manifest.ExpectedObjects {
		object := &manifest.ExpectedObjects[index]
		content := []byte(object.Type + "/" + object.Name)
		path := "/repo-a/" + object.Type
		if object.Type != "config" {
			path += "/" + object.Name
		}
		if code := restDo(t, client, http.MethodPost, path, content); code != http.StatusOK {
			t.Fatalf("seed %s = %d", path, code)
		}
		sum := sha256.Sum256(content)
		object.Bytes, object.Digest = int64(len(content)), "sha256:"+hex.EncodeToString(sum[:])
	}
	manifest.ExpectedObjectBytes = 0
	for _, object := range manifest.ExpectedObjects {
		manifest.ExpectedObjectBytes += object.Bytes
	}
	manifest.InventoryDigest = ExpectedInventoryDigest(manifest.ExpectedObjects)
	_, digest, err := CanonicalCreationManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	lease := ReadLease{LeaseID: "read-a", PointID: manifest.PointID, RepositoryID: manifest.RepositoryID, RecoveryEpoch: manifest.RecoveryEpoch, MaximumExpiresAt: time.Now().Add(time.Hour)}
	verifier, err := NewVerifierRESTServer(writer.root, uint32(os.Geteuid()), lease, allowingReadLeaseVerifier{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLocalInventory(context.Background(), manifest, digest, verifier); err != nil {
		t.Fatalf("complete inventory rejected: %v", err)
	}
	if err := os.Remove(filepath.Join(writer.root, "snapshots", manifest.SnapshotID)); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLocalInventory(context.Background(), manifest, digest, verifier); err == nil {
		t.Fatal("missing expected snapshot qualified")
	}
	if code := restRequestCode(t, verifier, http.MethodDelete, "/repo-a/data/"+manifest.ExpectedObjects[2].Name, nil); code != http.StatusForbidden {
		t.Fatalf("verifier deleted retained object: %d", code)
	}
}
