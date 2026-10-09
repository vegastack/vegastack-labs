package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func TestReplacementControlOwnershipCannotUseStatelessClass(t *testing.T) {
	f, _, request := actionDraftFixture(t)
	snapshot, err := NewGateRepository(f.s).ResolveHostAdmission(f.ctx, request.HostID)
	if err != nil {
		t.Fatal(err)
	}
	p := roleReservationPlan(t, request, snapshot)
	p.DeclarationID = "fixture-declaration"
	p.Binding.DeclarationRevision = 1
	p.PlanID = "control-role-intent"
	raw, _ := json.Marshal(p)
	digest := p.PlanDigest
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := f.s.conn.ExecContext(f.ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO immutable_plans VALUES(?,?,'fixture-declaration',1,1,0,?,?,?,?,?,?,'2026-01-01T00:00:00Z','2026-12-01T00:00:00Z')`, p.PlanID, digest, digest, digest, digest, raw, "fixture", digest)
	exec(`INSERT INTO plan_runs VALUES('control-role-run',?,?,'decision',NULL,'1.0.0','central','executor',?,'succeeded',0,'not-requested','pending',NULL,0,0,0,?,?,?,'now','now')`, p.PlanID, digest, digest, digest, digest, []byte(`{}`))
	exec(`INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,active_lease_id,result_digest,started_at,finished_at) VALUES('control-role-step','control-role-run',1,'role','host.action.execute','host-action','executor',?,?,?,1,'succeeded','verified',NULL,?,'now','now')`, request.HostID, digest, digest, digest)
	q := generated.HostReplacementRequest{OldHostID: request.HostID, OldIdentityDigest: p.HostRoleScope.SubjectIdentityDigest, OldRoleBindingDigest: p.HostRoleScope.RoleBindingDigest, RoleDeclarationID: p.DeclarationID, RoleDeclarationRevision: 1, ProfileLockDigest: p.HostRoleScope.ProfileLockDigest, RestorationClass: "control-database", Source: &generated.HostReplacementSourceReference{SourceBindingDigest: hostaction.Digest("source")}}
	for _, test := range []struct {
		name, class, proposed string
		source                bool
		pass                  bool
	}{
		{"control-current-owner", "control-database", "control", true, true},
		{"caller-stateless-no-source", "stateless-role", "control", false, false},
		{"caller-stateless-with-source", "stateless-role", "control", true, false},
		{"control-without-source", "control-database", "control", false, false},
		{"changed-proposed-role", "stateless-role", "application", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := q
			copy.RestorationClass = test.class
			if !test.source {
				copy.Source = nil
			}
			err := f.s.Read(context.Background(), func(tx ReadTx) error {
				return validateReplacementRestorationClass(func(query string, args ...any) *sql.Row { return tx.queryRow(context.Background(), query, args...) }, copy, test.proposed)
			})
			if test.pass && err != nil || !test.pass && Code(err) != generated.ErrorCodePrerequisiteBlocked {
				t.Fatalf("class validation: %v", err)
			}
		})
	}
}
