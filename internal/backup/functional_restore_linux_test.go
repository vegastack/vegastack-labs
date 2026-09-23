//go:build linux

package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type restoreRunnerFixture struct {
	snapshotID, capturedPath string
	bytes                    []byte
	modes                    []string
}

func (fixture *restoreRunnerFixture) Run(_ context.Context, request ResticRequest, _ *credentialref.Value) (ResticResult, error) {
	fixture.modes = append(fixture.modes, request.Mode)
	switch request.Mode {
	case "snapshots":
		return ResticResult{SnapshotIDs: []string{fixture.snapshotID}, SnapshotPaths: map[string][]string{fixture.snapshotID: {fixture.capturedPath}}, RepositoryFormat: 2, CompletedAt: time.Now().Add(-2 * time.Minute)}, nil
	case "check-full":
		return ResticResult{RepositoryFormat: 2, CompletedAt: time.Now().Add(-time.Minute)}, nil
	case "restore":
		path := filepath.Join(request.RestoreTarget, strings.TrimPrefix(fixture.capturedPath, "/"))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return ResticResult{}, err
		}
		if err := os.WriteFile(path, fixture.bytes, 0o600); err != nil {
			return ResticResult{}, err
		}
		return ResticResult{RepositoryFormat: 2, CompletedAt: time.Now()}, nil
	default:
		return ResticResult{}, errors.New("unexpected mode")
	}
}
func (*restoreRunnerFixture) Observation() ResticObservation { return ResticObservation{} }

type rejectingSQLiteInspector struct{}

func (rejectingSQLiteInspector) InspectSnapshot(context.Context, string, store.SnapshotExpectation) (store.SnapshotInspection, error) {
	return store.SnapshotInspection{}, errors.New("wrong catalog")
}

func TestFunctionalRestoreRejectsWrongCatalogAndPreservesAuthority(t *testing.T) {
	baseDir := t.TempDir()
	repositoryRoot := filepath.Join(baseDir, "repository")
	if err := os.Mkdir(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	authority := filepath.Join(baseDir, "authoritative.sqlite")
	if err := os.WriteFile(authority, []byte("authoritative"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshotID := strings.Repeat("a", 64)
	stage := filepath.Join(baseDir, ".vsk-backup-staging-original")
	path := filepath.Join(stage, "database.sqlite")
	content := []byte("restored fixture bytes")
	sum := sha256.Sum256(content)
	manifest := CreationManifest{PointID: "point-a", RepositoryID: "repo-a", RepositoryClass: "standard", SnapshotID: snapshotID, InventoryDigest: digest64("a"), ContentDigest: "sha256:" + hex.EncodeToString(sum[:]), CatalogDigest: digest64("b"), DatabaseSchemaVersion: 18, SourceRevision: 1, RecoveryEpoch: 0}
	inventory := LocalInventoryProof{PointID: manifest.PointID, SnapshotID: snapshotID, ManifestDigest: digest64("c"), InventoryDigest: manifest.InventoryDigest, ObservedDigest: manifest.InventoryDigest, RecoveryEpoch: 0}
	runner := &restoreRunnerFixture{snapshotID: snapshotID, capturedPath: path, bytes: content}
	password, err := credentialref.NewValue([]byte("fixture-only-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer password.Close()
	if _, err := VerifyFunctionalRestore(context.Background(), inventory, manifest, runner, ResticRequest{RepositoryRoot: repositoryRoot, RepositoryID: "repo-a", RepositoryClass: "standard"}, password, rejectingSQLiteInspector{}); err == nil {
		t.Fatal("wrong catalog qualified")
	}
	before, err := os.ReadFile(authority)
	if err != nil || string(before) != "authoritative" {
		t.Fatalf("authority changed: %q %v", before, err)
	}
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".vsk-backup-verify-") {
			t.Fatal("restore staging survived failure")
		}
	}
	if got := strings.Join(runner.modes, ","); got != "snapshots,check-full,restore" {
		t.Fatalf("verification modes=%q", got)
	}
}
