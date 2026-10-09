package hostaction

// NativeExecutionObservation describes the existing, immutable target-side
// execution claim and result. It does not infer a writer count from file count.
type NativeExecutionObservation struct {
	ExecutionDigest string
	BundleDigest    string
	ClaimDigest     string
	ResultDigest    string
	Status          string
}
