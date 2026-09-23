package backup

import "testing"

func TestLocalCapacityBlocksNewStandardAtEightyPercent(t *testing.T) {
	selection := RetirementSelection{Targets: []RetirementCandidate{retirementCandidate("old", 1, false)}, ExpectedInventoryDigest: retirementCandidate("old", 1, false).ManifestDigest}
	snapshot := CapacitySnapshot{TotalBytes: 1000, AvailableBytes: 200, RetainedBytes: 700, QuarantinedBytes: 100, ExpectedGrowthBytes: 0, RepackScratchBytes: 1}
	decision, err := ForecastLocalRetirement(selection, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if decision.AdmitNewStandard || decision.AdmitCritical || !decision.Warning || decision.ProjectedBytes != 801 {
		t.Fatalf("unsafe capacity decision: %#v", decision)
	}
}

func TestLocalCapacityRequiresMeasuredScratchAndHeadroom(t *testing.T) {
	selection := RetirementSelection{Targets: []RetirementCandidate{retirementCandidate("old", 1, false)}, ExpectedInventoryDigest: retirementCandidate("old", 1, false).ManifestDigest}
	snapshot := CapacitySnapshot{TotalBytes: 1000, AvailableBytes: 400, RetainedBytes: 500, ExpectedGrowthBytes: 50, RepackScratchBytes: 0}
	if _, err := ForecastLocalRetirement(selection, snapshot); err == nil {
		t.Fatal("unknown repack scratch admitted")
	}
	snapshot.RepackScratchBytes = 100
	decision, err := ForecastLocalRetirement(selection, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if decision.AdmitCritical || decision.AdmitNewStandard || decision.ProjectedBytes != 750 {
		t.Fatalf("thirty percent reserve lost: %#v", decision)
	}
	snapshot.RepackScratchBytes = 50
	decision, err = ForecastLocalRetirement(selection, snapshot)
	if err != nil || !decision.AdmitCritical || !decision.AdmitNewStandard || decision.ProjectedBytes != 700 {
		t.Fatalf("bounded critical capacity rejected: %#v %v", decision, err)
	}
}

func TestLocalCapacityRejectsImpossibleArithmeticAndQuarantine(t *testing.T) {
	selection := RetirementSelection{ExpectedInventoryDigest: retirementCandidate("old", 1, false).ManifestDigest}
	for _, snapshot := range []CapacitySnapshot{
		{TotalBytes: 1000, AvailableBytes: 1001},
		{TotalBytes: 1000, AvailableBytes: 100, QuarantinedBytes: 901},
		{TotalBytes: 1000, AvailableBytes: 100, ExpectedGrowthBytes: 9223372036854775807},
	} {
		if _, err := ForecastLocalRetirement(selection, snapshot); err == nil {
			t.Fatalf("impossible capacity admitted: %#v", snapshot)
		}
	}
}
