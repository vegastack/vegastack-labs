package hostaction

import (
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func measuredResult() generated.HostActionResult {
	d := Digest("test")
	m := generated.AccessMeasurement{Schema: generated.SchemaIDAccessMeasurement, SchemaVersion: "1.0.0", ControlID: "ssh-admin", Kind: "ssh", Status: "passed", SubjectHostID: "test-host", SubjectIdentityDigest: d, ProfileLockDigest: d, ProducerID: "test-producer", ProducerVersion: "1.0.0", BundleDigest: d, ObservedAt: time.Now().UTC().Format(time.RFC3339), ConfigurationDigest: d, PositiveProbeDigest: d, NegativeProbeDigest: d, Reason: "measured"}
	m.MeasurementDigest = MeasurementDigest(m)
	r := generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: d, Status: "succeeded", Reason: "verified", ControlMeasurements: []generated.AccessMeasurement{m}}
	r.ResultDigest = ResultDigest(r)
	return r
}
func TestMeasuredResultBindsEveryObservation(t *testing.T) {
	original := measuredResult()
	if err := ValidateResult(original); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"measurement", "bundle", "duplicate", "result", "size"} {
		t.Run(kind, func(t *testing.T) {
			r := measuredResult()
			switch kind {
			case "measurement":
				r.ControlMeasurements[0].Status = "failed"
			case "bundle":
				r.ControlMeasurements[0].BundleDigest = Digest("other")
			case "duplicate":
				r.ControlMeasurements = append(r.ControlMeasurements, r.ControlMeasurements[0])
			case "result":
				r.ResultDigest = Digest("other")
			case "size":
				r.ControlMeasurements[0].Reason = strings.Repeat("x", MaximumMeasurement+1)
			}
			if ValidateResult(r) == nil {
				t.Fatal("tampered result accepted")
			}
		})
	}
}
