//go:build linux

package nativecredential

import (
	"context"
	"os"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

// NewInstalledLoadedObserver rechecks existing enrollment and receipts. Neither
// construction nor ObserveLoaded calls Restart or creates lifecycle evidence.
func NewInstalledLoadedObserver(ctx context.Context, ciphertextRoot string, ownerUID uint32, receipts NativeReceiptReader) (LoadedObserver, error) {
	if receipts == nil {
		return nil, errNativeLifecycle
	}
	verifier, err := NewInstalledNativeLifecycleVerifier(ctx, ciphertextRoot, ownerUID)
	if err != nil {
		return nil, err
	}
	return &installedLoadedObserver{receipts: receipts, recheck: func(ctx context.Context, r credentialref.NativeLoadedReceipt, reader credentialref.NativeConsumerBinding) error {
		if verifier.policy(r.Binding) != nil {
			return errNativeLifecycle
		}
		return verifier.recheck(ctx, r.Binding, reader, r.Proof)
	}, currentPID: os.Getpid}, nil
}
