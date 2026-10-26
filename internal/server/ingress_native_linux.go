//go:build linux

package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"path/filepath"
	"slices"
)

func composeIngressNative(ctx context.Context, p serverconfig.Profile, path string, s *store.Store, registry *adapter.Registry) error {
	scope, e := store.NewGateRepository(s).GetAppliedProfileScope(ctx)
	if e != nil || !slices.Contains(scope.Capabilities, "credential.ingress.read") {
		return nil
	}
	resolver := hostActionNativeResolver{root: filepath.Join(filepath.Dir(path), "credential-drafts"), owner: p.SocketOwnerUID, references: store.NewCredentialRepository(s)}
	return registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: ingress.AdapterID, ProfileID: scope.ProfileID, CapabilityID: "credential.ingress.read", Enabled: true}, resolver)
}
