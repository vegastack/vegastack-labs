//go:build linux

package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter/localbackup"
	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestLoadedRecoveryCredentialResolverReadsExactActiveSystemdCredential(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	binding := credentialref.StepBinding{OperationID: "step-a", AdapterID: localbackup.AdapterID, TargetID: "repository-critical", ReferenceID: "backup-key", ConsumerID: localbackup.AdapterID, PurposeID: "backup-encryption", MaterialVersion: "version-a", ResolverID: "native-systemd", StateRevision: 8, RecoveryEpoch: 3}
	name := nativecredential.LoadedName(binding)
	if err := os.WriteFile(filepath.Join(directory, name), []byte("synthetic-recovery-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	activated := "2026-09-24T00:00:00Z"
	reference := generated.CredentialReference{ReferenceID: binding.ReferenceID, ConsumerID: binding.ConsumerID, PurposeID: binding.PurposeID, TargetID: binding.TargetID, ResolverID: binding.ResolverID, MaterialVersion: binding.MaterialVersion, Status: "active", StateRevision: binding.StateRevision, RecoveryEpoch: binding.RecoveryEpoch, ActivatedAt: &activated, VerifiedConsumerIDs: []string{binding.ConsumerID}}
	resolver := loadedRecoveryCredentialResolver{ownerUID: uint32(os.Geteuid()), repo: recoveryReferenceStub{reference: reference}}
	value, err := resolver.Resolve(context.Background(), binding)
	if err != nil || value == nil || string(value.Bytes()) != "synthetic-recovery-password" {
		t.Fatalf("resolve = (%v, %v)", value, err)
	}
	value.Close()
	binding.MaterialVersion = "version-b"
	if value, err := resolver.Resolve(context.Background(), binding); err == nil || value != nil {
		t.Fatalf("changed binding = (%v, %v)", value, err)
	}
}
