//go:build !linux && !darwin

package recovery

// The protected OS manifest source is unavailable on unqualified platforms.
func LoadSystemWitnessManifest(WitnessBinding) (PinnedWitness, error) {
	return PinnedWitness{}, ErrWitnessUnavailable
}
