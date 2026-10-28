package maintenance

import (
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"slices"
	"time"
)

const UnsupportedAdapter = "local.maintenance.unsupported"

// NextBatchReady only evaluates existing independently supplied prerequisites;
// it cannot authorize or execute a batch. Unknown/partial never mean success.
func NextBatchReady(targets []generated.MaintenanceTarget, canary string) bool {
	if len(targets) == 0 || targets[0].HostID != canary {
		return false
	}
	seen := map[string]bool{}
	for _, t := range targets {
		if seen[t.HostID] || debianaccess.ProtectedName(t.HostID) || t.Diagnosis != "healthy" || t.Canary != "passed" || t.Drain != "passed" || t.Health != "passed" || t.Recovery != "passed" {
			return false
		}
		seen[t.HostID] = true
	}
	return true
}
func Prepare(q generated.MaintenanceDraftRequest, diagnoses []generated.MaintenanceDiagnosis, actor, session string, now time.Time) (generated.MaintenanceRecord, error) {
	out := generated.MaintenanceRecord{Schema: generated.SchemaIDMaintenanceRecord, SchemaVersion: "1.0.0", Action: q.Action, Targets: []generated.MaintenanceTarget{}, CanaryHostID: q.CanaryHostID, CanaryRunID: q.CanaryRunID, Incident: q.Incident, PreparedByDigest: hostaction.Digest(actor), AgentSessionDigest: hostaction.Digest(session), PreparedAt: now.UTC().Format(time.RFC3339), StateRevision: q.ExpectedStateRevision, RecoveryEpoch: q.RecoveryEpoch, ReasonDigest: q.ReasonDigest, Blockers: []string{"maintenance-execution-unsupported"}, ExecutionAvailable: false}
	if !valid(generated.SchemaIDMaintenanceDraftRequest, q) || len(q.TargetIDs) == 0 || len(diagnoses) != len(q.TargetIDs) || q.TargetIDs[0] != q.CanaryHostID || now.IsZero() {
		return out, invalid()
	}
	if (q.Action == "incident-reconciliation") != (q.Incident != nil) {
		return out, invalid()
	}
	if i := q.Incident; i != nil {
		start, e1 := time.Parse(time.RFC3339, i.StartedAt)
		end, e2 := time.Parse(time.RFC3339, i.EndedAt)
		if e1 != nil || e2 != nil || end.Before(start) || end.After(now) || start.Before(now.Add(-30*24*time.Hour)) || len(i.EvidenceDigests) == 0 {
			return out, invalid()
		}
		for _, d := range i.EvidenceDigests {
			if len(d) != 71 || d[:7] != "sha256:" {
				return out, invalid()
			}
			for _, c := range d[7:] {
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
					return out, invalid()
				}
			}
		}
	}
	seen := map[string]bool{}
	for i, id := range q.TargetIDs {
		d := diagnoses[i]
		if seen[id] || debianaccess.ProtectedName(id) || !valid(generated.SchemaIDMaintenanceDiagnosis, d) || d.HostID != id || d.StateRevision != q.ExpectedStateRevision || d.RecoveryEpoch != q.RecoveryEpoch {
			return out, invalid()
		}
		seen[id] = true
		t := generated.MaintenanceTarget{Schema: generated.SchemaIDMaintenanceTarget, SchemaVersion: "1.0.0", HostID: id, BindingDigest: d.BindingDigest, ObservationDigest: d.ObservationDigest, Diagnosis: d.Status, Canary: "unknown", Drain: "unsupported", Health: "unknown", Recovery: "unknown"}
		out.Targets = append(out.Targets, t)
		if d.NewAdmissionBlocked && !slices.Contains(out.Blockers, "host-admission-blocked") {
			out.Blockers = append(out.Blockers, "host-admission-blocked")
		}
	}
	out.Blockers = append(out.Blockers, "canary-unverified", "drain-unsupported", "health-unverified", "recovery-unverified")
	if !valid(generated.SchemaIDMaintenanceRecord, out) {
		return out, invalid()
	}
	return out, nil
}

// Declaration persists only a review record in existing revision storage. The
// reserved unsupported adapter must never acquire an execution handler.
func Declaration(q generated.MaintenanceDraftRequest, r generated.MaintenanceRecord) (generated.DeclarationRevisionRequest, error) {
	if !valid(generated.SchemaIDMaintenanceDraftRequest, q) || !valid(generated.SchemaIDMaintenanceRecord, r) || r.ExecutionAvailable {
		return generated.DeclarationRevisionRequest{}, invalid()
	}
	d := hostaction.Digest(r)
	return generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: q.DeclarationID, DeclarationType: "maintenance.review", ExpectedRevision: q.ExpectedRevision, ExpectedStateRevision: q.ExpectedStateRevision, RecoveryEpoch: q.RecoveryEpoch, ReasonDigest: q.ReasonDigest, Maintenance: &r, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "maintenance-review", OperationType: "maintenance.review", AdapterID: UnsupportedAdapter, TargetID: q.DeclarationID, InputDigest: d, ArtifactDigest: d, Idempotent: true}}, Extensions: []generated.ContractExtension{{Name: "x-maintenance-record", ValueDigest: d}}}, nil
}
func ValidateDeclaration(d generated.DeclarationRevision) bool {
	present := d.Maintenance != nil || d.DeclarationType == "maintenance.review"
	for _, o := range d.Operations {
		present = present || o.AdapterID == UnsupportedAdapter || o.OperationType == "maintenance.review"
	}
	for _, e := range d.Extensions {
		present = present || e.Name == "x-maintenance-record"
	}
	if !present {
		return true
	}
	r := d.Maintenance
	if d.CIJob != nil || d.CIEnrollment != nil || d.HostingLifecycle != nil || d.ServiceRecovery != nil || d.ServiceDeployment != nil || d.ServiceImport != nil || d.NetworkEndpoint != nil || d.HostAliasClaim != nil || d.AuthorizationGrantBatch != nil {
		return false
	}
	if r == nil || d.DeclarationType != "maintenance.review" || !valid(generated.SchemaIDMaintenanceRecord, r) || r.ExecutionAvailable || len(d.Operations) != 1 || len(d.Extensions) != 1 || d.RecoveryEpoch != r.RecoveryEpoch || d.StateRevision != r.StateRevision+1 {
		return false
	}
	if len(r.Targets) == 0 || len(r.Targets) > 32 || r.Targets[0].HostID != r.CanaryHostID || (r.Action == "incident-reconciliation") != (r.Incident != nil) || !slices.Contains(r.Blockers, "maintenance-execution-unsupported") {
		return false
	}
	seen := map[string]bool{}
	for _, target := range r.Targets {
		if seen[target.HostID] || debianaccess.ProtectedName(target.HostID) {
			return false
		}
		seen[target.HostID] = true
	}
	op := d.Operations[0]
	sum := hostaction.Digest(r)
	return op.Sequence == 1 && op.OperationID == "maintenance-review" && op.OperationType == "maintenance.review" && op.AdapterID == UnsupportedAdapter && op.TargetID == d.DeclarationID && op.Idempotent && op.InputDigest == sum && op.ArtifactDigest == sum && d.Extensions[0].Name == "x-maintenance-record" && d.Extensions[0].ValueDigest == sum
}

// CanaryStatus reports a recorded exact-target failure without treating an
// unrelated successful operation as qualified maintenance health/recovery.
func CanaryStatus(run generated.Run, plan generated.Plan, host string, epoch int64) (string, error) {
	if run.RecoveryEpoch != epoch || run.PlanID != plan.PlanID || run.PlanDigest != plan.PlanDigest || plan.Binding.RecoveryEpoch != epoch || len(run.Steps) != 1 || run.Steps[0].TargetID != host {
		return "unknown", invalid()
	}
	switch {
	case run.Status == "failed" || run.Status == "cancelled":
		return "failed", nil
	case run.Status == "partial" || run.Steps[0].EffectState == "effect-unknown":
		return "partial", nil
	default:
		return "unknown", nil
	}
}
