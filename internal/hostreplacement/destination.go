package hostreplacement

import "github.com/vegastack/vegastack-labs/internal/generated"

// ReplacementDestination is observed by the existing registration, storage and
// candidate inspectors. It contains no writable path or caller pass boolean.
type ReplacementDestination struct {
	HostID, IdentityDigest, TargetDigest, ProfileLockDigest, PreservedPreimageDigest string
	CapacityBytes, SnapshotBytes, PreservedBytes                                     int64
	VolumeProofDigest, CandidatePreimageDigest                                       string
}

func ValidateDestination(in generated.HostReplacementRequest, observed ReplacementDestination) error {
	if ValidateInput(in) != nil || observed.HostID != in.NewHostID || observed.IdentityDigest != in.NewIdentityDigest || observed.TargetDigest != in.NewTargetDigest || observed.ProfileLockDigest != in.ProfileLockDigest || observed.PreservedPreimageDigest != in.PreservedPreimageDigest || observed.CapacityBytes <= 0 || observed.SnapshotBytes < 0 || observed.PreservedBytes < 0 || observed.PreservedBytes > observed.CapacityBytes || observed.SnapshotBytes > (observed.CapacityBytes-observed.PreservedBytes)/2 {
		return errInput
	}
	if in.RestorationClass == "control-database" && (observed.SnapshotBytes == 0 || observed.VolumeProofDigest == "" || observed.CandidatePreimageDigest == "") {
		return errInput
	}
	return nil
}
