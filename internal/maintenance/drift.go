// Package maintenance diagnoses authoritative observations and prepares inert
// records. It contains no host, provider, credential or execution transport.
package maintenance

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"time"
)

const MaximumAge = 86400 * time.Second

// Snapshot must be populated by the server from its current joined admission
// records. It is deliberately not accepted as an API request.
type Snapshot struct {
	HostID, IdentityDigest, BindingDigest string
	StateRevision, RecoveryEpoch          int64
	RequiredControls                      []string
	Controls                              []generated.HostControlResult
	Invalidated, AdmissionPassed          bool
}

func invalid() error { return failure.New(generated.ErrorCodeInputInvalid, "maintenance", false) }
func valid(schema string, value any) bool {
	raw, e := json.Marshal(value)
	return e == nil && generated.ValidateContractJSON(schema, raw, generated.ContractExact) == nil
}
func Diagnose(s Snapshot, now time.Time) (generated.MaintenanceDiagnosis, error) {
	out := generated.MaintenanceDiagnosis{Schema: generated.SchemaIDMaintenanceDiagnosis, SchemaVersion: "1.0.0", HostID: s.HostID, BindingDigest: s.BindingDigest, ObservationDigest: ObservationDigest(s.Controls, s.Invalidated), StateRevision: s.StateRevision, RecoveryEpoch: s.RecoveryEpoch, ObservedAt: now.UTC().Format(time.RFC3339), Status: "healthy", ExistingWorkloads: "unchanged", Findings: []generated.MaintenanceFinding{}}
	if !principal.ValidID(s.HostID) || debianaccess.ProtectedName(s.HostID) || now.IsZero() || len(s.RequiredControls) == 0 || len(s.RequiredControls) > 128 || len(s.Controls) > 256 {
		return out, invalid()
	}
	controls := map[string]generated.HostControlResult{}
	for _, c := range s.Controls {
		if _, ok := controls[c.ControlID]; ok {
			return out, invalid()
		}
		controls[c.ControlID] = c
	}
	seen := map[string]bool{}
	rank := map[string]int{"healthy": 0, "unknown": 1, "stale": 2, "failed": 3}
	for _, id := range s.RequiredControls {
		if !principal.ValidID(id) || seen[id] {
			return out, invalid()
		}
		seen[id] = true
		f := generated.MaintenanceFinding{Schema: generated.SchemaIDMaintenanceFinding, SchemaVersion: "1.0.0", ControlID: id, Status: "unknown", ReasonCode: "control-missing"}
		if c, ok := controls[id]; ok {
			observed, e := time.Parse(time.RFC3339Nano, c.ObservedAt)
			switch {
			case c.HostID != s.HostID || c.IdentityDigest != s.IdentityDigest || c.RecoveryEpoch != s.RecoveryEpoch || s.Invalidated:
				f.Status = "stale"
				f.ReasonCode = "binding-changed"
			case e != nil || observed.After(now):
				f.ReasonCode = "observation-time-invalid"
			case now.Sub(observed) > MaximumAge:
				f.Status = "stale"
				f.ReasonCode = "observation-expired"
			case c.Status == "failed":
				f.Status = "failed"
				f.ReasonCode = "control-failed"
			case c.Status == "passed":
				f.Status = "healthy"
				f.ReasonCode = "control-current"
			default:
				f.ReasonCode = "control-unresolved"
			}
		} else if s.Invalidated {
			f.Status = "stale"
			f.ReasonCode = "binding-changed"
		}
		if rank[f.Status] > rank[out.Status] {
			out.Status = f.Status
		}
		out.Findings = append(out.Findings, f)
	}
	out.NewAdmissionBlocked = out.Status != "healthy" || !s.AdmissionPassed
	if !valid(generated.SchemaIDMaintenanceDiagnosis, out) {
		return out, invalid()
	}
	return out, nil
}

func ObservationDigest(controls []generated.HostControlResult, invalidated bool) string {
	return hostaction.Digest(struct {
		Controls    []generated.HostControlResult
		Invalidated bool
	}{controls, invalidated})
}
