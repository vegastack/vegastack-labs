//go:build linux

package inventory_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestDecodeValidatePersistAndProjectDraft(t *testing.T) {
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
	service, err := inventory.NewService(store.NewInventoryDraftRepository(database), func() (inventory.DraftID, error) { return "draft-public-integration", nil })
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.ValidateAndStore(context.Background(), inventory.ImportRequest{IdempotencyKey: "integration-public", Decoded: decoded})
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
}
