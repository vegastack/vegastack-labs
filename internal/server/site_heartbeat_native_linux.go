//go:build linux

package server

import (
	"context"
	"path/filepath"
	"slices"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	r2adapter "github.com/vegastack/vegastack-labs/internal/adapters/r2"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func composeSiteHeartbeatNative(ctx context.Context, p serverconfig.Profile, path string, s *store.Store, registry *adapter.Registry) error {
	if p.OperationsHeartbeat == nil {
		return nil
	}
	scope, err := store.NewGateRepository(s).GetAppliedProfileScope(ctx)
	if err != nil || !slices.Contains(scope.Capabilities, heartbeatCredentialCapability) || !slices.Contains(scope.Capabilities, serverconfig.HeartbeatCapability(*p.OperationsHeartbeat)) {
		return nil
	}
	resolver := hostActionNativeResolver{root: filepath.Join(filepath.Dir(path), "credential-drafts"), owner: p.SocketOwnerUID, references: store.NewCredentialRepository(s)}
	return registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: r2adapter.HeartbeatConsumer, ProfileID: scope.ProfileID, CapabilityID: heartbeatCredentialCapability, Enabled: true}, resolver)
}
