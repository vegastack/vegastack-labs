//go:build linux

package nativecredential

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type syntheticReferenceInspector struct{ reference generated.CredentialReference }

func (inspector syntheticReferenceInspector) GetReference(context.Context, string) (generated.CredentialReference, error) {
	return inspector.reference, nil
}

type syntheticLoadedObserver struct{ loaded LoadedCredential }

func (observer syntheticLoadedObserver) ObserveLoaded(context.Context, credentialref.StepBinding) (LoadedCredential, error) {
	return observer.loaded, nil
}

func TestNativeResolverRequiresAppliedActiveVersionAndRestartObservation(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	binding := credentialref.StepBinding{OperationID: "operation-a", AdapterID: "adapter-a", TargetID: "service-a", ReferenceID: "ref-a", ConsumerID: "adapter-a", PurposeID: "deploy-a", MaterialVersion: "version-a", ResolverID: "native-a", StateRevision: 3, RecoveryEpoch: 0}
	name := LoadedName(binding)
	if err := os.WriteFile(filepath.Join(dir, name), []byte("synthetic-private-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	fingerprint := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	activated := "2026-09-16T00:00:00Z"
	reference := generated.CredentialReference{ReferenceID: binding.ReferenceID, ConsumerID: binding.ConsumerID, PurposeID: binding.PurposeID, TargetID: binding.TargetID, ResolverID: binding.ResolverID, MaterialVersion: binding.MaterialVersion, Fingerprint: fingerprint, Status: "active", StateRevision: 2, RecoveryEpoch: 0, ActivatedAt: &activated, VerifiedConsumerIDs: []string{binding.ConsumerID}}
	observer := syntheticLoadedObserver{loaded: LoadedCredential{Name: name, MaterialVersion: binding.MaterialVersion, CiphertextFingerprint: fingerprint, RestartObserved: true}}
	resolver, err := NewResolver(dir, uint32(os.Geteuid()), syntheticReferenceInspector{reference}, observer)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	value, err := resolver.Resolve(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	value.Close()
	if len(value.Bytes()) != 0 {
		t.Fatal("closed value readable")
	}
	blocked, err := NewResolver(dir, uint32(os.Geteuid()), syntheticReferenceInspector{reference}, syntheticLoadedObserver{loaded: LoadedCredential{Name: name, MaterialVersion: binding.MaterialVersion, CiphertextFingerprint: fingerprint}})
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	if _, err := blocked.Resolve(context.Background(), binding); err == nil {
		t.Fatal("pre-restart staged file resolved")
	}
	wrongConsumer := binding
	wrongConsumer.ConsumerID = "other-consumer"
	if _, err := resolver.Resolve(context.Background(), wrongConsumer); err == nil {
		t.Fatal("cross-consumer reference resolved")
	}
	wrongEpoch := binding
	wrongEpoch.RecoveryEpoch++
	if _, err := resolver.Resolve(context.Background(), wrongEpoch); err == nil {
		t.Fatal("old-host reference resolved after recovery epoch")
	}
	if err := os.Chmod(filepath.Join(dir, name), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), binding); err == nil {
		t.Fatal("world-readable loaded file resolved")
	}
	if err := os.Chmod(filepath.Join(dir, name), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), make([]byte, 4097), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), binding); err == nil {
		t.Fatal("oversize loaded file resolved")
	}
	if err := os.Remove(filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), binding); err == nil {
		t.Fatal("loaded symlink resolved")
	}
}
