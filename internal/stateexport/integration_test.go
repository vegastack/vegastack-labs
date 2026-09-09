//go:build linux

package stateexport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestSignedDraftExportIntegratesSQLiteAuditAndProtectedArtifacts(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(context.Background(), store.Config{DatabasePath: filepath.Join(directory, "control.db"), Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	file, err := os.Open(filepath.Join("..", "inventory", "testdata", "minimal.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := (inventory.JSONDecoder{}).Decode(context.Background(), file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	importer, err := inventory.NewService(store.NewInventoryDraftRepository(database), func() (inventory.DraftID, error) { return "draft-export-integration", nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "principal-test-1", Method: identity.LocalOSPeerMethod})
	imported, err := importer.ValidateAndStore(ctx, inventory.ImportRequest{IdempotencyKey: "import-export-integration", CorrelationID: "request-import-export", Decoded: decoded})
	if err != nil {
		t.Fatal(err)
	}
	exportRoot := filepath.Join(directory, "exports")
	if err := os.Mkdir(exportRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	artifacts, err := store.NewInventoryExportArtifactStore(store.InventoryExportArtifactConfig{Root: exportRoot, ExpectedUID: uint32(os.Geteuid())})
	if err != nil {
		t.Fatal(err)
	}
	trust := newIntegrationTrust(t)
	repository := store.NewInventoryExportRepository(database)
	service, err := stateexport.NewService(stateexport.Config{Source: repository, Audit: repository, Artifacts: artifacts, Signer: trust, Verifier: trust, Build: result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "synthetic-test-only-build"}})
	if err != nil {
		t.Fatal(err)
	}
	request := stateexport.Request{CorrelationID: "request-export-integration", IdempotencyKey: "export-integration", Draft: inventory.DraftRef{ID: imported.DraftID, Revision: imported.DraftRevision}}
	first, err := service.Export(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := service.Export(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.ContentDigest != retry.ContentDigest || string(first.CanonicalBytes) != string(retry.CanonicalBytes) || first.StateRevision != imported.StateRevision {
		t.Fatalf("first/retry/import = %#v / %#v / %#v", first, retry, imported)
	}
	pending, err := repository.PendingExportRequests(context.Background(), 64)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending = %#v, %v", pending, err)
	}
	current, err := artifacts.InspectCurrent(context.Background())
	if err != nil || current == nil || current.ContentDigest != first.ContentDigest {
		t.Fatalf("current = %#v, %v", current, err)
	}
	health, err := database.Health(context.Background())
	if err != nil || health.Revision.StateRevision != imported.StateRevision {
		t.Fatalf("health = %#v, %v", health, err)
	}
}

type integrationTrust struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func newIntegrationTrust(t *testing.T) *integrationTrust {
	t.Helper()
	seed := [ed25519.SeedSize]byte{4, 2, 4, 2, 4, 2, 4, 2, 4, 2, 4, 2, 4, 2, 4, 2, 4, 2, 4, 2, 4, 2, 4, 2, 4, 2, 4, 2, 4, 2, 4, 2}
	private := ed25519.NewKeyFromSeed(seed[:])
	return &integrationTrust{private: private, public: private.Public().(ed25519.PublicKey)}
}

func (trust *integrationTrust) Sign(ctx context.Context, request stateexport.SignRequest) (stateexport.DetachedSignature, error) {
	input, err := stateexport.SigningInput(request)
	if err != nil || ctx.Err() != nil {
		return stateexport.DetachedSignature{}, errors.New("sign unavailable")
	}
	spki, err := x509.MarshalPKIXPublicKey(trust.public)
	if err != nil {
		return stateexport.DetachedSignature{}, err
	}
	fingerprint := sha256.Sum256(spki)
	return stateexport.DetachedSignature{Algorithm: stateexport.SignatureAlgorithm, KeyID: "synthetic-test-only-integration", KeyFingerprint: "sha256:" + hex.EncodeToString(fingerprint[:]), Value: base64.RawURLEncoding.EncodeToString(ed25519.Sign(trust.private, input))}, nil
}

func (trust *integrationTrust) Verify(ctx context.Context, request stateexport.SignRequest, signature stateexport.DetachedSignature) error {
	input, err := stateexport.SigningInput(request)
	if err != nil || ctx.Err() != nil {
		return errors.New("verify unavailable")
	}
	spki, err := x509.MarshalPKIXPublicKey(trust.public)
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(spki)
	decoded, err := base64.RawURLEncoding.DecodeString(signature.Value)
	if err != nil || signature.KeyID != "synthetic-test-only-integration" || signature.KeyFingerprint != "sha256:"+hex.EncodeToString(fingerprint[:]) || !ed25519.Verify(trust.public, input, decoded) {
		return errors.New("verify failed")
	}
	return nil
}
