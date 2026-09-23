//go:build linux

package server

import (
	"context"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/sys/unix"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/localbackup"
	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

const recoveryBackupCredentialCapability = "credential.backup.read"

type loadedRecoveryCredentialResolver struct {
	ownerUID uint32
	repo     recoveryCredentialReferences
}

func (resolver loadedRecoveryCredentialResolver) Resolve(ctx context.Context, binding credentialref.StepBinding) (*credentialref.Value, error) {
	blocked := func() (*credentialref.Value, error) {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-local-credential", false)
	}
	if ctx == nil || resolver.repo == nil || binding.ResolverID != "native-systemd" || binding.ConsumerID != localbackup.AdapterID || !credentialref.ValidBinding(binding) {
		return blocked()
	}
	reference, err := resolver.repo.GetActiveVersion(ctx, binding.ReferenceID, binding.RecoveryEpoch)
	if err != nil || reference.ReferenceID != binding.ReferenceID || reference.ConsumerID != binding.ConsumerID || reference.PurposeID != binding.PurposeID || reference.TargetID != binding.TargetID || reference.ResolverID != binding.ResolverID || reference.MaterialVersion != binding.MaterialVersion || reference.Status != "active" || reference.ActivatedAt == nil || reference.StateRevision > binding.StateRevision || !slices.Contains(reference.VerifiedConsumerIDs, binding.ConsumerID) {
		return blocked()
	}
	directoryPath := os.Getenv("CREDENTIALS_DIRECTORY")
	if !filepath.IsAbs(directoryPath) || filepath.Clean(directoryPath) != directoryPath {
		return blocked()
	}
	fd, err := unix.Open(directoryPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return blocked()
	}
	directory := os.NewFile(uintptr(fd), "recovery-loaded-credentials")
	defer directory.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != resolver.ownerUID || stat.Mode&0o077 != 0 {
		return blocked()
	}
	raw, err := nativecredential.ReadLoadedBytes(ctx, directory, nativecredential.LoadedName(binding), resolver.ownerUID)
	if err != nil {
		return blocked()
	}
	defer func() {
		for index := range raw {
			raw[index] = 0
		}
	}()
	value, err := credentialref.NewValue(raw)
	if err != nil {
		return blocked()
	}
	return value, nil
}

func registerProductionRecoveryCredentialResolver(ctx context.Context, registry *adapter.Registry, repository *store.CredentialRepository, profiles *store.GateRepository, ownerUID uint32) error {
	if ctx == nil || registry == nil || repository == nil || profiles == nil {
		return failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-local-credential", false)
	}
	profile, err := profiles.GetAppliedProfileScope(ctx)
	if err != nil || !slices.Contains(profile.Capabilities, recoveryBackupCredentialCapability) {
		return nil
	}
	return registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: localbackup.AdapterID, ProfileID: profile.ProfileID, CapabilityID: recoveryBackupCredentialCapability, Enabled: true}, loadedRecoveryCredentialResolver{ownerUID: ownerUID, repo: repository})
}
