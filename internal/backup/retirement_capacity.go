package backup

import (
	"math"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// CapacitySnapshot is measured on the repository filesystem before an inert
// retention proposal is considered. Retained and quarantined bytes are both
// subsets of used space; neither may be treated as immediate reclaim.
type CapacitySnapshot struct {
	TotalBytes, AvailableBytes, RetainedBytes, QuarantinedBytes int64
	ExpectedGrowthBytes, RepackScratchBytes                     int64
}

type CapacityDecision struct {
	Warning, AdmitNewStandard, AdmitCritical bool
	ProjectedBytes, HeadroomBytes            int64
}

// ForecastLocalRetirement keeps a 30 percent projected reserve through one
// bounded repack cycle. It never credits estimated reclaim bytes or silently
// ignores quarantine, and requires measured scratch for any proposed target.
func ForecastLocalRetirement(selection RetirementSelection, capacity CapacitySnapshot) (CapacityDecision, error) {
	invalid := func() (CapacityDecision, error) {
		return CapacityDecision{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "local-retirement-capacity", false)
	}
	if !validBackupManifestDigest(selection.ExpectedInventoryDigest) || capacity.TotalBytes <= 0 || capacity.AvailableBytes < 0 || capacity.AvailableBytes > capacity.TotalBytes || capacity.RetainedBytes < 0 || capacity.QuarantinedBytes < 0 || capacity.ExpectedGrowthBytes < 0 || capacity.RepackScratchBytes < 0 || (len(selection.Targets) > 0 && capacity.RepackScratchBytes == 0) {
		return invalid()
	}
	used := capacity.TotalBytes - capacity.AvailableBytes
	if capacity.RetainedBytes > used || capacity.QuarantinedBytes > used-capacity.RetainedBytes {
		return invalid()
	}
	projected := used
	for _, extra := range []int64{capacity.ExpectedGrowthBytes, capacity.RepackScratchBytes} {
		if extra > math.MaxInt64-projected {
			return invalid()
		}
		projected += extra
	}
	if projected > capacity.TotalBytes {
		return invalid()
	}
	reserveLimit := capacity.TotalBytes/10*7 + (capacity.TotalBytes%10)*7/10
	standardStop := capacity.TotalBytes/10*8 + (capacity.TotalBytes%10)*8/10
	admits := projected <= reserveLimit
	return CapacityDecision{Warning: used >= reserveLimit, AdmitNewStandard: used < standardStop && admits, AdmitCritical: admits, ProjectedBytes: projected, HeadroomBytes: capacity.TotalBytes - projected}, nil
}
