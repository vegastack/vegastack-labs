//go:build linux

package server

import (
	"context"
	"path/filepath"

	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/run"
)

func composeNativeCredentialLifecycleVerifier(ctx context.Context, databasePath string, ownerUID uint32) run.CredentialLifecycleVerifier {
	root := filepath.Join(filepath.Dir(databasePath), "credential-drafts")
	verifier, err := nativecredential.NewInstalledNativeLifecycleVerifier(ctx, root, ownerUID)
	if err != nil {
		return run.UnavailableCredentialLifecycleVerifier{}
	}
	return verifier
}
