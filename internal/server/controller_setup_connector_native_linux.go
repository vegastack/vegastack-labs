//go:build linux

package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"path/filepath"
)

func observeControllerConnectorNative(ctx context.Context, profile serverconfig.Profile, s *store.Store, path string, p generated.Plan, c generated.IngressChange) error {
	refs := store.NewCredentialRepository(s)
	observer, e := nativecredential.NewInstalledLoadedObserver(ctx, filepath.Join(filepath.Dir(path), "credential-drafts"), profile.SocketOwnerUID, refs)
	if e != nil {
		return actionFailure()
	}
	// Existing observer checks current service invocation, exact source/loaded
	// inode and positive/denied readers. It never resolves credential plaintext.
	return checkControllerConnectorNative(ctx, p, c, refs, func(ctx context.Context, b credentialref.StepBinding) error {
		loaded, e := observer.ObserveLoaded(ctx, b)
		if e != nil || !loaded.RestartObserved || loaded.MaterialVersion != b.MaterialVersion {
			return actionFailure()
		}
		return nil
	})
}
