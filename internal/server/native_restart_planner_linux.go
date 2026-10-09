//go:build linux

package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/store"
	"path/filepath"
)

type nativeRestartPlanner struct {
	references *store.CredentialRepository
	native     *nativecredential.NativeLifecycleVerifier
}

func (p nativeRestartPlanner) PrepareContinuation(ctx context.Context, b credentialref.LifecycleBinding, runID, stepID string) (*credentialref.NativeRestartContinuation, error) {
	pending, err := p.references.ReadNativeRestartPending(ctx, runID, stepID)
	if err != nil {
		return nil, err
	}
	c, err := p.native.CaptureNativeRestartContinuation(ctx, pending)
	if err != nil {
		return nil, err
	}
	b.NativeRestartContinuation = c
	if !credentialref.PendingMatchesLifecycle(pending, b) {
		return nil, actionFailure()
	}
	return c, nil
}
func composeNativeRestartPlanner(ctx context.Context, path string, owner uint32, references *store.CredentialRepository) api.CredentialNativeRestartPlanner {
	native, err := nativecredential.NewInstalledNativeLifecycleVerifier(ctx, filepath.Join(filepath.Dir(path), "credential-drafts"), owner)
	if err != nil {
		return nil
	}
	return nativeRestartPlanner{references: references, native: native}
}
