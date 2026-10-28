//go:build linux

package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"path/filepath"
	"slices"
)

func composeCIPublicationNative(ctx context.Context, p serverconfig.Profile, path string, s *store.Store, registry *adapter.Registry) error {
	if len(p.CIPublicationBindings) == 0 {
		return nil
	}
	scope, e := store.NewGateRepository(s).GetAppliedProfileScope(ctx)
	if e != nil || !slices.Contains(scope.Capabilities, "credential.registry.push") {
		return serviceFailure("PREREQUISITE_BLOCKED")
	}
	resolver := hostActionNativeResolver{root: filepath.Join(filepath.Dir(path), "credential-drafts"), owner: p.SocketOwnerUID, references: store.NewCredentialRepository(s)}
	return registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: store.CIPublicationAdapter, ProfileID: scope.ProfileID, CapabilityID: "credential.registry.push", Enabled: true}, resolver)
}
