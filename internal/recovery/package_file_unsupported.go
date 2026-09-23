//go:build !linux && !darwin

package recovery

import "context"

type InstalledPackage struct {
	Pin      PinnedWitness
	Witness  SignedWitness
	Envelope ProtectedEnvelope
}

func LoadSystemRecoveryPackage(context.Context, WitnessBinding) (InstalledPackage, error) {
	return InstalledPackage{}, ErrWitnessUnavailable
}
