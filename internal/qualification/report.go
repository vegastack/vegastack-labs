package qualification

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"time"
)

// ValidateNativeReport validates complete diagnostic reports, never confers
// admission. Authoritative qualification additionally resolves product lineage.
func ValidateNativeReport(report generated.NativeReport) error {
	raw, err := json.Marshal(report)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDNativeReport, raw, generated.ContractExact) != nil || len(report.PendingRequirements) != 0 || len(report.Scenarios) != len(scenarioCatalog) {
		return ErrUnavailable
	}
	start, err := time.Parse(time.RFC3339, report.StartedAt)
	finish, e := time.Parse(time.RFC3339, report.FinishedAt)
	if err != nil || e != nil || finish.Before(start) || finish.Sub(start) > 4*time.Hour {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	for _, s := range report.Scenarios {
		if !knownScenario(s.ScenarioID) || seen[s.ScenarioID] || s.Status != "passed" || s.QualificationClass != "native" || s.ExecutableDigest != report.ExecutableDigest || s.ProfileLockDigest != report.ProfileLockDigest || s.ArtifactDigest == "" || (s.BeforeStateDigest == "") != (s.AfterStateDigest == "") || (ScenarioRequiresStatePair(s.ScenarioID) && s.BeforeStateDigest == "") || len(s.PositiveObservationDigests) == 0 || len(s.NegativeObservationDigests) == 0 || len(s.ProducerRunIDs) == 0 || len(s.ProducerReceiptDigests) == 0 || len(s.NativeObservationDigests) == 0 || (s.RecoveryResult != "passed" && s.RecoveryResult != "not-required") || s.CleanupResult != "passed" {
			return ErrUnavailable
		}
		a, e := time.Parse(time.RFC3339, s.StartedAt)
		b, f := time.Parse(time.RFC3339, s.FinishedAt)
		if e != nil || f != nil || a.Before(start) || b.After(finish) || b.Before(a) {
			return ErrUnavailable
		}
		seen[s.ScenarioID] = true
	}
	return nil
}
