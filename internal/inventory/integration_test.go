//go:build linux

package inventory_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestDecodeValidatePersistAndProjectDraft(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "control.db")
	database, err := store.Open(context.Background(), store.Config{DatabasePath: databasePath, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	file, err := os.Open("testdata/minimal.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoded, err := (inventory.JSONDecoder{}).Decode(context.Background(), file)
	if err != nil {
		t.Fatal(err)
	}
	service, err := inventory.NewService(store.NewInventoryDraftRepository(database), func() (inventory.DraftID, error) { return "draft-public-integration", nil }, []audit.OutboxRequirement{{Destination: "audit-primary", Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "principal-test-1", Method: identity.LocalOSPeerMethod})
	request := inventory.ImportRequest{IdempotencyKey: "integration-public", CorrelationID: "request-integration-public", Decoded: decoded}
	result, err := service.ValidateAndStore(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := store.NewInventoryDraftRepository(database).SnapshotDraft(context.Background(), inventory.DraftRef{ID: result.DraftID, Revision: result.DraftRevision})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Created || result.ValidationStatus != inventory.DraftValid || projection.Kind != "draft" || projection.ContentDigest != result.ContentDigest || !strings.HasPrefix(result.SourceDigest, "sha256:") {
		t.Fatalf("result/projection = %#v / %#v", result, projection)
	}
	replay, err := service.ValidateAndStore(ctx, request)
	if err != nil || replay.Created || replay.EventID != result.EventID || replay.StateRevision != result.StateRevision {
		t.Fatalf("replay/result = %#v / %#v, %v", replay, result, err)
	}
	canary := "github_pat_public-integration-canary"
	rejected := decoded
	rejected.Candidate.Assets[0].Identities[0].Value = canary
	_, rejectedErr := service.ValidateAndStore(ctx, inventory.ImportRequest{IdempotencyKey: "integration-rejected", CorrelationID: "request-integration-rejected", Decoded: rejected})
	if rejectedErr == nil || strings.Contains(rejectedErr.Error(), canary) {
		t.Fatalf("unsafe rejection = %v", rejectedErr)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	for _, artifact := range []string{databasePath, databasePath + "-journal"} {
		raw, readErr := os.ReadFile(artifact)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal(readErr)
		}
		if bytes.Contains(raw, []byte(canary)) {
			t.Fatalf("rejected public canary persisted in %s", filepath.Base(artifact))
		}
	}
}

func TestDanglingProvenancePersistsAsCompleteBlockedDraft(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(context.Background(), store.Config{DatabasePath: filepath.Join(directory, "control.db"), Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	file, err := os.Open("testdata/minimal.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoded, err := (inventory.JSONDecoder{}).Decode(context.Background(), file)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Candidate.Provenance[0].RecordID = "missing-record"
	service, err := inventory.NewService(store.NewInventoryDraftRepository(database), func() (inventory.DraftID, error) { return "draft-public-dangling-provenance", nil }, []audit.OutboxRequirement{{Destination: "audit-primary", Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "principal-test-1", Method: identity.LocalOSPeerMethod})
	result, err := service.ValidateAndStore(ctx, inventory.ImportRequest{IdempotencyKey: "integration-dangling-provenance", CorrelationID: "request-dangling-provenance", Decoded: decoded})
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := store.NewInventoryDraftRepository(database).Get(context.Background(), inventory.DraftRef{ID: result.DraftID, Revision: result.DraftRevision})
	if err != nil {
		t.Fatal(err)
	}
	if result.ValidationStatus != inventory.DraftBlocked || len(persisted.Provenance) != 1 || persisted.Provenance[0].RecordID != "missing-record" || len(persisted.Findings) != 1 || persisted.Findings[0].Code != "MISSING_REFERENCE" || result.StateRevision != 1 {
		t.Fatalf("dangling provenance draft was not persisted completely: %#v / %#v", result, persisted)
	}
}
