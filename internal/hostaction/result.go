package hostaction

import (
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

const MaximumMeasurement = 16384
const MaximumMeasurements = 8

// MeasurementDigest omits only its own digest; all actual observations remain bound.
func MeasurementDigest(m generated.AccessMeasurement) string {
	m.MeasurementDigest = ""
	return Digest(m)
}

// ResultDigest binds the complete canonical result, including measurement bytes.
func ResultDigest(r generated.HostActionResult) string { r.ResultDigest = ""; return Digest(r) }
func ValidateResult(r generated.HostActionResult) error {
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaximumResultFrame || generated.ValidateContractJSON(generated.SchemaIDHostActionResult, raw, generated.ContractExact) != nil || len(r.ControlMeasurements) > MaximumMeasurements {
		return blocked()
	}
	seen := map[string]bool{}
	for _, m := range r.ControlMeasurements {
		raw, e := json.Marshal(m)
		if e != nil || len(raw) > MaximumMeasurement || generated.ValidateContractJSON(generated.SchemaIDAccessMeasurement, raw, generated.ContractExact) != nil || m.BundleDigest != r.BundleDigest || m.MeasurementDigest != MeasurementDigest(m) || seen[m.ControlID] {
			return blocked()
		}
		seen[m.ControlID] = true
	}
	if len(r.ControlMeasurements) > 0 && r.ResultDigest != ResultDigest(r) {
		return blocked()
	}
	return nil
}
