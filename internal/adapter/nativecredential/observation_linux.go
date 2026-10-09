//go:build linux

package nativecredential

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"path/filepath"
)

// NativeOSObservation supplies only OS reads. Lifecycle matching, ciphertext
// inspection, positive/denied verification and receipt creation stay here.
// Production composition exclusively uses NewInstalledNativeLifecycleVerifier.
type NativeOSObservation struct {
	PolicyBytes func() ([]byte, error)
	Process     func(context.Context, AppliedUnitSnapshot, credentialref.NativeConsumerBinding) (ProcessIdentity, error)
}

func NewNativeLifecycleVerifierWithObservation(authority NativeAuthority, units AppliedUnitReader, root string, owner uint32, observation NativeOSObservation) (*NativeLifecycleVerifier, error) {
	if authority == nil || units == nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || observation.PolicyBytes == nil || observation.Process == nil {
		return nil, errNativeLifecycle
	}
	v := &NativeLifecycleVerifier{Authority: authority, Units: units, CiphertextRoot: root, CiphertextOwnerUID: owner, process: observation.Process}
	v.policy = func(b credentialref.LifecycleBinding) error {
		raw, err := observation.PolicyBytes()
		if err != nil {
			return errNativeLifecycle
		}
		p, err := parseProbePolicy(raw)
		if err != nil {
			return errNativeLifecycle
		}
		return matchNativePolicy(p, b)
	}
	observer := invocationObserver{units: units, authority: authority, root: root, ownerUID: owner, inspect: InspectEncrypted, process: observation.Process}
	v.observe = observer.observe
	v.recheck = v.recheckProof
	v.current = v.currentNativeProof
	return v, nil
}
