package backup

import (
	"strings"
	"testing"
)

func digest64(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func validCreationManifest(t *testing.T) CreationManifest {
	t.Helper()
	objects := []ExpectedObject{
		{Type: "config", Name: "config", Bytes: 155, Digest: digest64("a")},
		{Type: "keys", Name: strings.Repeat("f", 64), Bytes: 256, Digest: digest64("b")},
		{Type: "data", Name: strings.Repeat("b", 64), Bytes: 4096, Digest: digest64("c")},
		{Type: "snapshots", Name: strings.Repeat("1", 64), Bytes: 512, Digest: digest64("e")},
	}
	var total int64
	for _, object := range objects {
		total += object.Bytes
	}
	dependencies := []ExpectedDependency{{DependencyID: "dep-a", Kind: "binary", Digest: digest64("7")}}
	return CreationManifest{
		Schema: CreationManifestSchema, SchemaVersion: CreationManifestVersion,
		PolicyID: "policy-a", PolicyDigest: digest64("f"), PointID: "point-a", RunID: "run-a", StepID: "step-a",
		RepositoryID: "repo-a", RepositoryClass: "standard", SourceID: "source-a", SourceSelectors: []string{"selector-a"}, SourceRevision: 3, RecoveryEpoch: 0,
		DatabaseSchemaVersion: 17, CatalogDigest: digest64("3"), ContentDigest: digest64("4"),
		ConsistencyHookID: "sqlite-online", ConsistencySuccess: true,
		SnapshotID: strings.Repeat("1", 64), SnapshotCount: 1,
		ExpectedObjectCount: int64(len(objects)), ExpectedObjectBytes: total,
		InventoryDigest: ExpectedInventoryDigest(objects), ExpectedObjects: objects,
		DependencyInventoryDigest: ExpectedDependencyInventoryDigest(dependencies), ExpectedDependencies: dependencies,
		KeyReferenceID: "enc-a", ResticDigest: digest64("9"), PlatformDigest: digest64("8"),
		StartedAt: "2026-09-18T00:00:00Z", CompletedAt: "2026-09-18T00:01:00Z",
	}
}

func TestCanonicalCreationManifestRoundTrips(t *testing.T) {
	canonical, digest, err := CanonicalCreationManifest(validCreationManifest(t))
	if err != nil || len(canonical) == 0 || !validBackupManifestDigest(digest) {
		t.Fatalf("canonical = %d bytes, digest=%q, err=%v", len(canonical), digest, err)
	}
}

func TestCanonicalManifestRejectsInconsistentInventory(t *testing.T) {
	t.Run("wrong object count", func(t *testing.T) {
		manifest := validCreationManifest(t)
		manifest.ExpectedObjectCount++
		if _, _, err := CanonicalCreationManifest(manifest); codeOf(err) != "INTEGRITY_FAILURE" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("truncated inventory digest", func(t *testing.T) {
		manifest := validCreationManifest(t)
		manifest.InventoryDigest = ExpectedInventoryDigest(manifest.ExpectedObjects[:len(manifest.ExpectedObjects)-1])
		if _, _, err := CanonicalCreationManifest(manifest); codeOf(err) != "INTEGRITY_FAILURE" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("wrong byte total", func(t *testing.T) {
		manifest := validCreationManifest(t)
		manifest.ExpectedObjectBytes += 1
		if _, _, err := CanonicalCreationManifest(manifest); codeOf(err) != "INTEGRITY_FAILURE" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("failed consistency", func(t *testing.T) {
		manifest := validCreationManifest(t)
		manifest.ConsistencySuccess = false
		if _, _, err := CanonicalCreationManifest(manifest); codeOf(err) != "INTEGRITY_FAILURE" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing dependency", func(t *testing.T) {
		manifest := validCreationManifest(t)
		manifest.ExpectedDependencies = []ExpectedDependency{}
		if _, _, err := CanonicalCreationManifest(manifest); codeOf(err) != "INTEGRITY_FAILURE" {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestExpectedInventoryDigestIsOrderIndependent(t *testing.T) {
	objects := validCreationManifest(t).ExpectedObjects
	reversed := make([]ExpectedObject, len(objects))
	for index := range objects {
		reversed[len(objects)-1-index] = objects[index]
	}
	if ExpectedInventoryDigest(objects) != ExpectedInventoryDigest(reversed) {
		t.Fatal("inventory digest depends on order")
	}
	altered := append([]ExpectedObject(nil), objects...)
	altered[0].Bytes++
	if ExpectedInventoryDigest(objects) == ExpectedInventoryDigest(altered) {
		t.Fatal("inventory digest ignored a changed object")
	}
}
