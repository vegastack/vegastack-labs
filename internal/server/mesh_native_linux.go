//go:build linux

package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	mesh "github.com/vegastack/vegastack-labs/internal/networkmesh"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"path/filepath"
	"slices"
)

func composeMeshNative(ctx context.Context, p serverconfig.Profile, path string, s *store.Store, registry *adapter.Registry) error {
	scope, e := store.NewGateRepository(s).GetAppliedProfileScope(ctx)
	if e != nil || !slices.Contains(scope.Capabilities, "credential.mesh.read") {
		return nil
	}
	resolver := hostActionNativeResolver{root: filepath.Join(filepath.Dir(path), "credential-drafts"), owner: p.SocketOwnerUID, references: store.NewCredentialRepository(s)}
	return registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: mesh.AdapterID, ProfileID: scope.ProfileID, CapabilityID: "credential.mesh.read", Enabled: true}, resolver)
}
