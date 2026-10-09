//go:build linux

package server

import (
	"context"
	"path/filepath"
	"slices"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	transport "github.com/vegastack/vegastack-labs/internal/adapter/hostaction"
	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func composeHostActions(ctx context.Context, p serverconfig.Profile, databasePath string, s *store.Store, registry *adapter.Registry, gates *store.GateRepository) (func(), error) {
	noop := func() {}
	if p.HostActionSignerPath == "" {
		return noop, nil
	}
	repository := store.NewHostActionRepository(s)
	signer, err := newProtectedActionSigner(ctx, p.HostActionSignerPath, p.HostActionKeyID, p.SocketOwnerUID)
	if err != nil {
		return noop, err
	}
	authority, err := NewHostActionAuthority(repository, signer, time.Now)
	if err != nil {
		return noop, err
	}
	composition := hostAccessComposition{store: s, hosts: repository, gates: gates, allowed: slices.Clone(p.HostActionIdentityDigests)}
	impl, err := transport.NewWithAccess(hostActionTargets{repository: repository, allowed: slices.Clone(p.HostActionIdentityDigests)}, &HostActionBundleIssuer{Repository: repository, Signer: signer, Clock: time.Now}, authority, composition, debianaccess.NewLocalProbe(debianaccess.LocalProbeRuntime{Sources: debianaccess.NewNativeSourceResolver()}), composition)
	if err != nil {
		return noop, err
	}
	references := store.NewCredentialRepository(s)
	resolver := hostActionNativeResolver{root: filepath.Join(filepath.Dir(databasePath), "credential-drafts"), owner: p.SocketOwnerUID, references: references}
	cleanup := noop
	scope, err := store.NewGateRepository(s).GetAppliedProfileScope(ctx)
	if err != nil || !slices.Contains(scope.Capabilities, "credential.host-action.read") {
		cleanup()
		return noop, actionFailure()
	}
	if err = registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: hostaction.AdapterID, ProfileID: scope.ProfileID, CapabilityID: "credential.host-action.read", Enabled: true}, resolver); err != nil {
		cleanup()
		return noop, err
	}
	if err = registry.Register(hostaction.AdapterID, impl); err != nil {
		cleanup()
		return noop, err
	}
	return cleanup, nil
}

// Resolve opens the current systemd credential namespace at point of use. This
// lets the same server stage and activate its first credential before a loaded
// credential exists; absence still denies action execution.
type hostActionNativeResolver struct {
	root       string
	owner      uint32
	references *store.CredentialRepository
}

func (r hostActionNativeResolver) Resolve(ctx context.Context, b credentialref.StepBinding) (*credentialref.Value, error) {
	observer, err := nativecredential.NewInstalledLoadedObserver(ctx, r.root, r.owner, r.references)
	if err != nil {
		return nil, err
	}
	resolver, err := nativecredential.NewResolverFromEnvironment(r.owner, r.references, observer)
	if err != nil {
		return nil, err
	}
	defer resolver.Close()
	return resolver.Resolve(ctx, b)
}
