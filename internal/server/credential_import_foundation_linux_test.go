//go:build linux

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type persistentCredentialFixtureStager struct {
	root       string
	stageCalls *int
}

func (stager persistentCredentialFixtureStager) Inspect(_ context.Context, name string) (nativecredential.CiphertextInspection, error) {
	content, err := os.ReadFile(filepath.Join(stager.root, name))
	if os.IsNotExist(err) {
		return nativecredential.CiphertextInspection{State: "absent"}, nil
	}
	if err != nil {
		return nativecredential.CiphertextInspection{}, err
	}
	sum := sha256.Sum256(content)
	return nativecredential.CiphertextInspection{State: "present", Fingerprint: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

func (stager persistentCredentialFixtureStager) Stage(_ context.Context, private []byte, name string) (string, error) {
	(*stager.stageCalls)++
	privateDigest := sha256.Sum256(private)
	envelope := []byte("SYNTHETIC-ENCRYPTED-ENVELOPE:" + hex.EncodeToString(privateDigest[:]))
	path := filepath.Join(stager.root, name)
	if err := os.WriteFile(path, envelope, 0o600); err != nil {
		return "", err
	}
	sum := sha256.Sum256(envelope)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func TestImportedDraftSurvivesRestartButCannotBecomeLiveAuthority(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	ciphertextDirectory := filepath.Join(directory, "credential-drafts")
	if err := os.Mkdir(ciphertextDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "control.db")
	config := store.Config{DatabasePath: databasePath, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test"}
	authority, err := store.Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	stageCalls := 0
	stager := persistentCredentialFixtureStager{root: ciphertextDirectory, stageCalls: &stageCalls}
	input := generated.CredentialImportRequest{Schema: generated.SchemaIDCredentialImportRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 0, RecoveryEpoch: 0, IdempotencyKey: "import-a", ReferenceID: "ref-a", ConsumerID: "consumer-a", PurposeID: "purpose-a", TargetID: "target-a", ResolverID: "native-systemd", MaterialVersion: "version-a"}
	input.TargetDigest = credentialref.ImportTargetDigest(input)
	principal := identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}
	firstImporter := newCredentialImporter(store.NewCredentialRepository(authority), store.NewPlanRepository(authority), stager)
	first, err := firstImporter.Import(context.Background(), input, []byte("synthetic-private-canary"), principal)
	if err != nil || first.Status != "draft" || stageCalls != 1 {
		t.Fatalf("first import = %#v, %v, stage calls %d", first, err, stageCalls)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}

	config.Mode = store.OpenExisting
	authority, err = store.Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	repository := store.NewCredentialRepository(authority)
	secondImporter := newCredentialImporter(repository, store.NewPlanRepository(authority), persistentCredentialFixtureStager{root: ciphertextDirectory, stageCalls: &stageCalls})
	retry, err := secondImporter.Import(context.Background(), input, []byte("different-private-canary"), principal)
	if err != nil || retry != first || stageCalls != 1 {
		t.Fatalf("restart retry = %#v, %v, stage calls %d", retry, err, stageCalls)
	}
	if _, err := repository.GetReference(context.Background(), input.ReferenceID); store.Code(err) != generated.ErrorCodeResourceNotFound {
		t.Fatalf("inert import became current credential authority: %v", err)
	}
	registry := productionAdapterRegistry()
	if _, err := registry.ResolveCredentialResolver("native-systemd", input.ConsumerID, input.TargetID); adapter.Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("production resolver became available: %v", err)
	}
	if err := (runengine.UnavailableGateVerifier{}).VerifySecretStep(context.Background(), generated.Plan{}, generated.PlanOperation{}); runengine.Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("live secret gate became available: %v", err)
	}
	entries, err := os.ReadDir(ciphertextDirectory)
	if err != nil || len(entries) != 1 || strings.Contains(entries[0].Name(), "private") {
		t.Fatalf("ciphertext directory = %#v, %v", entries, err)
	}
}
