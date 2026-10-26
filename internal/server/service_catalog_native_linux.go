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

func composeServiceCatalogNative(ctx context.Context, p serverconfig.Profile, path string, s *store.Store, registry *adapter.Registry) error {
	scope, err := store.NewGateRepository(s).GetAppliedProfileScope(ctx)
	if err != nil {
		return nil
	}
	resolver := hostActionNativeResolver{root: filepath.Join(filepath.Dir(path), "credential-drafts"), owner: p.SocketOwnerUID, references: store.NewCredentialRepository(s)}
	for _, entry := range []struct{ consumer, capability string }{{"service.environment", "credential.service-environment.read"}, {"service.recovery", "credential.service-recovery.mutate"}, {"service.recovery.repository", "credential.service-recovery.repository"}, {"registry.harbor.manage", "credential.registry.manage"}, {"registry.harbor.ci", "credential.registry.push"}, {"registry.harbor.deploy", "credential.registry.pull"}, {"hosting.coolify", "credential.hosting.read"}, {"registry.harbor", "credential.registry.read"}, {"hosting.coolify.deploy", "credential.hosting.deploy"}, {"service.runtime", "credential.service-runtime.read"}} {
		if !slices.Contains(scope.Capabilities, entry.capability) {
			continue
		}
		if err := registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: entry.consumer, ProfileID: scope.ProfileID, CapabilityID: entry.capability, Enabled: true}, resolver); err != nil {
			return err
		}
	}
	return nil
}
