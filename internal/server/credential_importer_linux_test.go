//go:build linux

package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type fakeCredentialCiphertextStager struct {
	inspect     nativecredential.CiphertextInspection
	inspectErr  error
	stageErr    error
	stageCalls  int
	name        string
	fingerprint string
	stagePanic  bool
	stageHook   func()
}

func (fake *fakeCredentialCiphertextStager) Inspect(context.Context, string) (nativecredential.CiphertextInspection, error) {
	return fake.inspect, fake.inspectErr
}

func (fake *fakeCredentialCiphertextStager) Stage(_ context.Context, private []byte, name string) (string, error) {
	fake.stageCalls++
	fake.name = name
	if fake.stagePanic {
		panic("synthetic-private-canary")
	}
	if fake.stageErr != nil {
		return "", fake.stageErr
	}
	fake.fingerprint = "sha256:" + strings.Repeat("b", 64)
	fake.inspect = nativecredential.CiphertextInspection{State: "present", Fingerprint: fake.fingerprint}
	if fake.stageHook != nil {
		fake.stageHook()
	}
	return fake.fingerprint, nil
}

func TestCredentialImportRejectsChangedBindingAndEpochBeforeStage(t *testing.T) {
	importer, stager, input, principal := credentialImporterFixture(t)
	changed := input
	changed.TargetDigest = "sha256:" + strings.Repeat("a", 64)
	if result, err := importer.Preflight(context.Background(), changed, principal); err == nil || result != nil || stager.stageCalls != 0 {
		t.Fatalf("changed digest admitted: %#v %v", result, err)
	}
	changed = input
	changed.RecoveryEpoch++
	changed.TargetDigest = credentialref.ImportTargetDigest(changed)
	if result, err := importer.Preflight(context.Background(), changed, principal); err == nil || result != nil || stager.stageCalls != 0 {
		t.Fatalf("changed epoch admitted: %#v %v", result, err)
	}
}

func TestCredentialImportPanicIsSanitizedAndWipesPrivateInput(t *testing.T) {
	importer, stager, input, principal := credentialImporterFixture(t)
	stager.stagePanic = true
	private := []byte("synthetic-private-canary")
	result, err := importer.Import(context.Background(), input, private, principal)
	stable, _ := failure.As(err)
	if stable == nil || stable.Code != generated.ErrorCodeRecoveryRequired || result.DraftID != "" || strings.Contains(err.Error(), "synthetic-private-canary") {
		t.Fatalf("panic result=%#v err=%v", result, err)
	}
	for _, value := range private {
		if value != 0 {
			t.Fatal("panic input was not wiped")
		}
	}
}

func TestCredentialImportConcurrentSameRequestReturnsOneDraft(t *testing.T) {
	importer, stager, input, principal := credentialImporterFixture(t)
	const workers = 6
	type outcome struct {
		value generated.CredentialImportSubmission
		err   error
	}
	results := make(chan outcome, workers)
	for index := range workers {
		go func(index int) {
			private := []byte("synthetic-private-canary-" + string(rune('a'+index)))
			value, err := importer.Import(context.Background(), input, private, principal)
			results <- outcome{value: value, err: err}
		}(index)
	}
	var first generated.CredentialImportSubmission
	for range workers {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent import: %v", result.err)
		}
		if first.DraftID == "" {
			first = result.value
		} else if result.value != first {
			t.Fatalf("drafts differ: %#v %#v", first, result.value)
		}
	}
	if stager.stageCalls != 1 {
		t.Fatalf("stage calls=%d", stager.stageCalls)
	}
}

func credentialImporterFixture(t *testing.T) (*credentialImporter, *fakeCredentialCiphertextStager, generated.CredentialImportRequest, identity.Principal) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: filepath.Join(directory, "control.db"), Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "0.0.0-test", BuildVersion: "build-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	stager := &fakeCredentialCiphertextStager{inspect: nativecredential.CiphertextInspection{State: "absent"}}
	importer := newCredentialImporter(store.NewCredentialRepository(authority), store.NewPlanRepository(authority), stager)
	input := generated.CredentialImportRequest{Schema: generated.SchemaIDCredentialImportRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 0, RecoveryEpoch: 0, IdempotencyKey: "import-a", ReferenceID: "ref-a", ConsumerID: "consumer-a", PurposeID: "purpose-a", TargetID: "target-a", ResolverID: "native-systemd", MaterialVersion: "version-a"}
	input.TargetDigest = credentialref.ImportTargetDigest(input)
	return importer, stager, input, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}
}

func TestCredentialImportRetryClassifiesPromotedOrphanBeforePrivateRead(t *testing.T) {
	importer, stager, input, principal := credentialImporterFixture(t)
	stager.inspect = nativecredential.CiphertextInspection{State: "present", Fingerprint: "sha256:" + strings.Repeat("a", 64)}
	submission, err := importer.Preflight(context.Background(), input, principal)
	stable, _ := failure.As(err)
	if stable == nil || stable.Code != generated.ErrorCodeRecoveryRequired || submission != nil {
		t.Fatalf("orphan admitted: %#v %v", submission, err)
	}
	if stager.stageCalls != 0 {
		t.Fatal("orphan was overwritten")
	}
}

func TestCredentialImportCancellationStopsBeforeStage(t *testing.T) {
	importer, stager, input, principal := credentialImporterFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := importer.Import(ctx, input, []byte("synthetic-private-canary"), principal); err == nil || result.DraftID != "" || stager.stageCalls != 0 {
		t.Fatalf("cancelled import = %#v, %v, stage calls %d", result, err, stager.stageCalls)
	}
}

func TestCredentialImportDatabaseFailureAfterPromotionRequiresRecovery(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	config := store.Config{DatabasePath: filepath.Join(directory, "control.db"), Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test"}
	authority, err := store.Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	stager := &fakeCredentialCiphertextStager{inspect: nativecredential.CiphertextInspection{State: "absent"}, stageHook: func() { _ = authority.Close() }}
	importer := newCredentialImporter(store.NewCredentialRepository(authority), store.NewPlanRepository(authority), stager)
	input := generated.CredentialImportRequest{Schema: generated.SchemaIDCredentialImportRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 0, RecoveryEpoch: 0, IdempotencyKey: "import-a", ReferenceID: "ref-a", ConsumerID: "consumer-a", PurposeID: "purpose-a", TargetID: "target-a", ResolverID: "native-systemd", MaterialVersion: "version-a"}
	input.TargetDigest = credentialref.ImportTargetDigest(input)
	principal := identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}
	result, err := importer.Import(context.Background(), input, []byte("synthetic-private-canary"), principal)
	stable, _ := failure.As(err)
	if stable == nil || stable.Code != generated.ErrorCodeRecoveryRequired || result.DraftID != "" || stager.stageCalls != 1 {
		t.Fatalf("post-promotion failure = %#v, %v, stage calls %d", result, err, stager.stageCalls)
	}

	config.Mode = store.OpenExisting
	authority, err = store.Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	restarted := newCredentialImporter(store.NewCredentialRepository(authority), store.NewPlanRepository(authority), stager)
	if existing, err := restarted.Preflight(context.Background(), input, principal); err == nil || existing != nil {
		t.Fatalf("promoted orphan was not recovery-blocked: %#v, %v", existing, err)
	}
}

func TestNativeImportCreatesOneInertDraftAndExactRetry(t *testing.T) {
	importer, stager, input, principal := credentialImporterFixture(t)
	private := []byte("synthetic-private-canary")
	first, err := importer.Import(context.Background(), input, private, principal)
	if err != nil || first.Status != "draft" || first.ReferenceID != input.ReferenceID || stager.stageCalls != 1 {
		t.Fatalf("first=%#v err=%v calls=%d", first, err, stager.stageCalls)
	}
	for _, value := range private {
		if value != 0 {
			t.Fatal("private input was not wiped")
		}
	}
	retryPrivate := []byte("different-private-canary")
	second, err := importer.Import(context.Background(), input, retryPrivate, principal)
	if err != nil || second != first || stager.stageCalls != 1 {
		t.Fatalf("retry=%#v err=%v calls=%d", second, err, stager.stageCalls)
	}
	for _, value := range retryPrivate {
		if value != 0 {
			t.Fatal("retry input was not wiped")
		}
	}
}
