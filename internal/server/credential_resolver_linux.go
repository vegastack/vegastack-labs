//go:build linux

package server

import (
	"context"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/sys/unix"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/adapter/onepassword"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type credentialAppliedProfile interface {
	GetAppliedProfileScope(context.Context) (store.GateAppliedProfile, error)
}
type credentialRevisionReader interface {
	CurrentRevision(context.Context) (store.RevisionToken, error)
}

// composeOptionalOnePasswordCredential is dormant until the server has an
// applied capability/profile and a native loaded service token. It is never
// invoked by default production composition or the unregistered #104 gate.
func composeOptionalOnePasswordCredential(ctx context.Context, ownerUID uint32, tokenName string, registry *adapter.Registry, capability adapter.CredentialCapabilityScope, config onepassword.Config, profiles credentialAppliedProfile, revisions credentialRevisionReader, api onepassword.SecretsAPI) error {
	blocked := func(target string) error { return failure.New(generated.ErrorCodePrerequisiteBlocked, target, false) }
	if ctx == nil || registry == nil || profiles == nil || revisions == nil || !capability.Enabled || capability.ResolverID != config.ResolverID || capability.ConsumerID != config.ConsumerID || capability.CapabilityID != "credential.onepassword.read" {
		return blocked("onepassword-capability")
	}
	profile, err := profiles.GetAppliedProfileScope(ctx)
	if err != nil {
		return blocked("onepassword-profile")
	}
	current, err := revisions.CurrentRevision(ctx)
	if err != nil || profile.ProfileID != capability.ProfileID || profile.RecoveryEpoch != current.RecoveryEpoch || profile.StateRevision > current.StateRevision || !slices.Contains(profile.Capabilities, capability.CapabilityID) {
		return blocked("onepassword-profile")
	}
	if _, err := credentialref.ParseID(tokenName); err != nil {
		return blocked("onepassword-token-name")
	}
	directoryPath := os.Getenv("CREDENTIALS_DIRECTORY")
	if !filepath.IsAbs(directoryPath) || filepath.Clean(directoryPath) != directoryPath {
		return blocked("onepassword-native-credential-directory")
	}
	fd, err := unix.Open(directoryPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return blocked("onepassword-native-credential-directory")
	}
	directory := os.NewFile(uintptr(fd), "native-service-credentials")
	defer directory.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != ownerUID || stat.Mode&0o077 != 0 {
		return blocked("onepassword-native-credential-directory")
	}
	tokenBytes, err := nativecredential.ReadLoadedBytes(ctx, directory, tokenName, ownerUID)
	if err != nil {
		return blocked("onepassword-native-token")
	}
	defer zeroCredential(tokenBytes)
	token, err := credentialref.NewValue(tokenBytes)
	if err != nil {
		return blocked("onepassword-native-token")
	}
	resolver, err := onepassword.NewResolver(ctx, token, config, api)
	if err != nil {
		return blocked("onepassword-resolver")
	}
	if err := registry.RegisterCredentialResolver(capability, resolver); err != nil {
		return blocked("onepassword-resolver-registration")
	}
	return nil
}
