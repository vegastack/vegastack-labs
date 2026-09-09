//go:build linux

package stateexport_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestExportArtifactsEventsAndDiagnosticsExcludePublicCanaries(t *testing.T) {
	var fixture struct {
		ForbiddenValues []string `json:"forbiddenValues"`
	}
	fixtureBytes, err := os.ReadFile(filepath.Join("testdata", "public-canaries.json"))
	if err != nil || json.Unmarshal(fixtureBytes, &fixture) != nil || len(fixture.ForbiddenValues) == 0 {
		t.Fatalf("fixture = %#v, %v", fixture, err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "control.db")
	database, err := store.Open(context.Background(), store.Config{DatabasePath: databasePath, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join("..", "inventory", "testdata", "minimal.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := (inventory.JSONDecoder{}).Decode(context.Background(), file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	importer, err := inventory.NewService(store.NewInventoryDraftRepository(database), func() (inventory.DraftID, error) { return "draft-redaction-test", nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "principal-test-1", Method: identity.LocalOSPeerMethod})
	imported, err := importer.ValidateAndStore(ctx, inventory.ImportRequest{IdempotencyKey: "import-redaction-test", CorrelationID: "request-import-redaction", Decoded: decoded})
	if err != nil {
		t.Fatal(err)
	}
	rejected := decoded
	rejected.Candidate.Assets[0].Identities[0].Value = fixture.ForbiddenValues[0]
	_, rejectedErr := importer.ValidateAndStore(ctx, inventory.ImportRequest{IdempotencyKey: "import-redaction-rejected", CorrelationID: "request-import-redaction-rejected", Decoded: rejected})
	if rejectedErr == nil {
		t.Fatal("private-shaped input was accepted")
	}
	exportRoot := filepath.Join(directory, "exports")
	if err := os.Mkdir(exportRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	artifacts, err := store.NewInventoryExportArtifactStore(store.InventoryExportArtifactConfig{Root: exportRoot, ExpectedUID: uint32(os.Geteuid())})
	if err != nil {
		t.Fatal(err)
	}
	repository := store.NewInventoryExportRepository(database)
	trust := newIntegrationTrust(t)
	service, err := stateexport.NewService(stateexport.Config{Source: repository, Audit: repository, Artifacts: artifacts, Signer: trust, Verifier: trust, Build: result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "synthetic-test-only-build"}})
	if err != nil {
		t.Fatal(err)
	}
	draft := inventory.DraftRef{ID: imported.DraftID, Revision: imported.DraftRevision}
	success, err := service.Export(ctx, stateexport.Request{CorrelationID: "request-redaction-success", IdempotencyKey: "export-redaction-success", Draft: draft})
	if err != nil {
		t.Fatal(err)
	}
	unsafeSigner := &canaryErrorSigner{message: strings.Join(fixture.ForbiddenValues, "|")}
	failingService, err := stateexport.NewService(stateexport.Config{Source: repository, Audit: repository, Artifacts: artifacts, Signer: unsafeSigner, Verifier: trust, Build: result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "synthetic-test-only-build"}})
	if err != nil {
		t.Fatal(err)
	}
	_, exportErr := failingService.Export(ctx, stateexport.Request{CorrelationID: "request-redaction-failure", IdempotencyKey: "export-redaction-failure", Draft: draft})
	if stable, ok := failure.As(exportErr); !ok || stable.Code != "DEPENDENCY_UNAVAILABLE" {
		t.Fatalf("failure = %v", exportErr)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	serialized := [][]byte{success.CanonicalBytes, []byte(rejectedErr.Error()), []byte(exportErr.Error())}
	err = filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		serialized = append(serialized, raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range serialized {
		for _, canary := range fixture.ForbiddenValues {
			if bytes.Contains(raw, []byte(canary)) {
				t.Fatal("private canary reached a serialized or durable surface")
			}
		}
	}
}

type canaryErrorSigner struct{ message string }

func (signer *canaryErrorSigner) Sign(context.Context, stateexport.SignRequest) (stateexport.DetachedSignature, error) {
	return stateexport.DetachedSignature{}, errors.New(signer.message)
}
