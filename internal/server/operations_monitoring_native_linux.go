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

func composeOperationsNative(ctx context.Context, p serverconfig.Profile, path string, s *store.Store, r *adapter.Registry) error {
	scope, e := store.NewGateRepository(s).GetAppliedProfileScope(ctx)
	if e != nil {
		return nil
	}
	resolver := hostActionNativeResolver{root: filepath.Join(filepath.Dir(path), "credential-drafts"), owner: p.SocketOwnerUID, references: store.NewCredentialRepository(s)}
	for _, entry := range []struct {
		consumer, cap string
		enabled       bool
	}{{"operations.beszel", "credential.operations.read", len(p.OperationsBeszel) > 0}, {"operations.github-alerts", "credential.operations.notify", p.OperationsGithub != nil}} {
		if entry.enabled && slices.Contains(scope.Capabilities, entry.cap) {
			if e = r.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: entry.consumer, ProfileID: scope.ProfileID, CapabilityID: entry.cap, Enabled: true}, resolver); e != nil {
				return e
			}
		}
	}
	return nil
}
