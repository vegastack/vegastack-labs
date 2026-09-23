//go:build linux

package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestRetentionLockDraftCreatesExactInertDeclarationAndCatalog(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC) }
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: filepath.Join(directory, "control.db"), Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "retention-test", BuildVersion: "retention-test", Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	repository := store.NewLocalRetirementRepository(authority)
	revisions := store.NewPlanRepository(authority)
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), clock)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewRetentionLockDraftService(repository, revisions, declarations, &effectiveAuthorizationStub{})
	if err != nil {
		t.Fatal(err)
	}
	catalog := generated.LocalRetentionLockCatalog{Schema: generated.SchemaIDLocalRetentionLockCatalog, SchemaVersion: "1.0.0", RepositoryID: backupidentity.StandardRepository, RepositoryClass: "standard", SourceCoverageDigest: store.LocalPromiseSourceCoverageDigest(), RecoveryEpoch: 0, Revision: 2, Complete: true, Locks: []generated.BackupRetentionLock{}}
	_, digest, err := store.CanonicalLocalRetentionLockCatalog(retentionLockCatalog(catalog))
	if err != nil {
		t.Fatal(err)
	}
	input := generated.BackupRetentionLockDraftRequest{Schema: generated.SchemaIDBackupRetentionLockDraftRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 0, RecoveryEpoch: 0, TargetDigest: digest, IdempotencyKey: "retention-lock-draft-a", Catalog: catalog}
	principal := identity.Principal{ID: "operator-retention", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	submission, err := service.CreateDraft(context.Background(), input, principal)
	if err != nil || submission.CatalogDigest != digest || submission.StateRevision != 2 {
		t.Fatalf("submission=%#v err=%v", submission, err)
	}
	document, err := declarations.Get(context.Background(), submission.ChangeID, 1)
	if err != nil || document.DeclarationType != "backup.retention-locks" || len(document.Operations) != 1 || document.Operations[0].InputDigest != digest || document.Operations[0].ArtifactDigest != catalog.SourceCoverageDigest || len(document.Extensions) != 1 || document.Extensions[0].ValueDigest != digest {
		t.Fatalf("declaration=%#v err=%v", document, err)
	}
	replay, err := service.CreateDraft(context.Background(), input, principal)
	if err != nil || replay.DraftID != submission.DraftID || replay.StateRevision != submission.StateRevision {
		t.Fatalf("replay=%#v err=%v", replay, err)
	}
}
