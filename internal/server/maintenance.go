package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/maintenance"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
	"slices"
	"time"
)

type maintenanceSource struct {
	gates *store.GateRepository
	runs  *store.RunRepository
	plans *store.PlanRepository
	clock func() time.Time
}

func (s maintenanceSource) Diagnose(ctx context.Context, id string) (generated.MaintenanceDiagnosis, error) {
	snapshot, e := s.gates.ResolveMaintenanceHost(ctx, id)
	if e != nil {
		return generated.MaintenanceDiagnosis{}, e
	}
	passed := false
	if applied, e := s.gates.GetAppliedProfileScope(ctx); e == nil {
		scope := gate.ResolvedScope{ProfileID: applied.ProfileID, ProfileVersion: applied.ProfileVersion, PolicyID: applied.PolicyID, PolicyVersion: applied.PolicyVersion, Capabilities: applied.Capabilities, StateRevision: applied.StateRevision, RecoveryEpoch: applied.RecoveryEpoch}
		decision, e := gate.EvaluateHostAdmission(ctx, snapshot, scope, "host.hardening-baseline", s.clock())
		passed = e == nil && decision.Outcome == "passed"
	}
	return maintenance.Diagnose(maintenance.Snapshot{HostID: id, IdentityDigest: snapshot.IdentityDigest, BindingDigest: snapshot.BindingDigest, StateRevision: snapshot.Revision.StateRevision, RecoveryEpoch: snapshot.Revision.RecoveryEpoch, RequiredControls: append([]string{}, debianbaseline.ControlIDs...), Controls: snapshot.Results, Invalidated: slices.Contains(snapshot.Blockers, "host-binding-changed"), AdmissionPassed: passed}, s.clock())
}
func (s maintenanceSource) Prepare(ctx context.Context, q generated.MaintenanceDraftRequest, session string) (generated.DeclarationRevisionRequest, error) {
	actor, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return generated.DeclarationRevisionRequest{}, serviceFailure(generated.ErrorCodeAuthenticationRequired)
	}
	diagnoses := make([]generated.MaintenanceDiagnosis, 0, len(q.TargetIDs))
	for _, id := range q.TargetIDs {
		d, e := s.Diagnose(ctx, id)
		if e != nil {
			return generated.DeclarationRevisionRequest{}, e
		}
		diagnoses = append(diagnoses, d)
	}
	r, e := maintenance.Prepare(q, diagnoses, actor.ID, session, s.clock())
	if e != nil {
		return generated.DeclarationRevisionRequest{}, e
	}
	if q.CanaryRunID != "" {
		run, e := s.runs.Get(ctx, q.CanaryRunID)
		if e != nil {
			return generated.DeclarationRevisionRequest{}, e
		}
		p, e := s.plans.GetPlan(ctx, run.PlanID)
		if e != nil {
			return generated.DeclarationRevisionRequest{}, e
		}
		status, e := maintenance.CanaryStatus(run, p.Plan, q.CanaryHostID, q.RecoveryEpoch)
		if e != nil {
			return generated.DeclarationRevisionRequest{}, e
		}
		r.Targets[0].Canary = status
		if status == "failed" || status == "partial" {
			r.Blockers = append(r.Blockers, "canary-stops-next-batch")
		}
	}
	return maintenance.Declaration(q, r)
}
func registerMaintenance(app *api.Application, authority *store.Store, declarations *change.Service, factory *result.Factory) error {
	source := maintenanceSource{gates: store.NewGateRepository(authority), runs: store.NewRunRepository(authority), plans: store.NewPlanRepository(authority), clock: time.Now}
	return api.RegisterMaintenanceOperations(app, api.MaintenanceOperations{Diagnose: source.Diagnose, Prepare: source.Prepare, Declarations: declarations, Results: factory})
}
