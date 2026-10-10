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
	return NewLoadedObserver(verifier, receipts)
}

// NewLoadedObserver binds the verifier's OS observations to durable receipts.
func NewLoadedObserver(verifier *NativeLifecycleVerifier, receipts NativeReceiptReader) (LoadedObserver, error) {
	if verifier == nil || receipts == nil {
		return nil, errNativeLifecycle
	}
	return &installedLoadedObserver{receipts: receipts, currentProof: func(ctx context.Context, r credentialref.NativeLoadedReceipt, reader credentialref.NativeConsumerBinding) (credentialref.NativeInvocationMetadata, error) {
		if verifier.policy(r.Binding) != nil || verifier.current == nil || verifier.Authority == nil {
			return credentialref.NativeInvocationMetadata{}, errNativeLifecycle
		}
		proof, err := verifier.current(ctx, r.Binding, reader)
		if err != nil || proof.MainPID != uint32(os.Getpid()) || !validNativeProof(proof, reader, r.Binding) {
			return credentialref.NativeInvocationMetadata{}, errNativeLifecycle
		}
		for _, denied := range r.Binding.NativeDeniedReaders {
			result, err := verifier.Authority.Probe(ctx, AccessProbeRequest{UID: denied.ReaderUID, GID: denied.ReaderGID, UnitName: reader.UnitName, CredentialName: reader.LoadedName, MainPID: int(proof.MainPID), ProcessStartTicks: proof.ProcessStartTicks, BootID: proof.BootID})
			if err != nil || !validProbeResult(result) || result.Status != AccessProbeDenied || ctx.Err() != nil {
				return credentialref.NativeInvocationMetadata{}, errNativeLifecycle
			}
		}
		return proof, nil
	}, recheck: func(ctx context.Context, r credentialref.NativeLoadedReceipt, reader credentialref.NativeConsumerBinding) error {
		if verifier.policy(r.Binding) != nil {
			return errNativeLifecycle
		}
		return verifier.recheck(ctx, r.Binding, reader, r.Proof)
	}, currentPID: os.Getpid}, nil
}
