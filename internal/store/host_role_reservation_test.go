package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"os"
	"testing"
)

func roleReservationPlan(t *testing.T, request generated.HostActionRequest, s HostAdmissionSnapshot) generated.Plan {
	t.Helper()
	var in generated.LinuxRoleInput
	raw, err := os.ReadFile("../gate/testdata/linux-role-input.json")
	if err != nil || json.Unmarshal(raw, &in) != nil {
		t.Fatal(err)
	}
	in.HostID = request.HostID
	in.HostIdentityDigest = request.ConsoleConfirmation.HostIdentityDigest
	request.CallerUID = in.AutomationUID
	in.Accounts[0].UID = request.CallerUID
	for i := range in.Directories {
		in.Directories[i].UID = request.CallerUID
	}
	in.NetworkAccess.HostID = in.HostID
	in.NetworkAccess.HostIdentityDigest = in.HostIdentityDigest
	in.NetworkAccess.AutomationUID = in.AutomationUID
	in.NetworkAccess.RollbackSpecification.HostID = in.HostID
	in.NetworkAccess.RollbackSpecification.HostIdentityDigest = in.HostIdentityDigest
	in.NetworkAccess.RollbackDigest = hostaction.Digest(in.NetworkAccess.RollbackSpecification)
	in.CurrentRoleBindingDigest = s.RoleBindingDigest
	in.BaselineSnapshotDigest = HostAdmissionSnapshotDigest(s)
	in.RenderedPolicyDigest = linuxrole.PolicyDigest(in)
	in.RoleBindingDigest = linuxrole.RoleBindingDigest(in)
	raw, _ = json.Marshal(in)
	request.ActionID = "debian.role.apply"
	request.ActionInput = string(raw)
	request.ActionInputDigest = hostaction.BytesDigest(raw)
	request.AutomationPrincipalID = "operator-a"
	scope, err := linuxrole.ScopeForRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return generated.Plan{PlanID: "role-plan", PlanDigest: hostaction.Digest(request), AuthorizationBranch: "human", ExecutorMode: "central", Risk: "infrastructure", HostAction: &request, HostRoleScope: scope, Binding: generated.PlanBinding{StateRevision: s.Revision.StateRevision, RecoveryEpoch: s.Revision.RecoveryEpoch}, Operations: []generated.PlanOperation{{Sequence: 1, OperationType: "host.action.execute", TargetID: request.HostID}}}
}
func TestRoleReservationRechecksInsideWriterTransaction(t *testing.T) {
	for _, mode := range []string{"first-host-role", "changed-identity", "revoked-read", "revoked-execute", "revoked-ack"} {
		t.Run(mode, func(t *testing.T) {
			f, _, request := actionDraftFixture(t)
			gates := NewGateRepository(f.s)
			snapshot, err := gates.ResolveHostAdmission(f.ctx, request.HostID)
			if err != nil {
				t.Fatal(err)
			}
			p := roleReservationPlan(t, request, snapshot)
			// Existing adoption fixture supplies the consumed exact human/run identity;
			// this test exercises current policy in the role reservation transaction.
			var runID string
			if err = f.s.conn.QueryRowContext(f.ctx, `SELECT run_id FROM plan_run_steps LIMIT 1`).Scan(&runID); err != nil {
				t.Fatal(err)
			}
			if _, err = f.s.conn.ExecContext(f.ctx, `INSERT INTO effective_authorization_grants VALUES('role-execute','operator-a','infrastructure-admin','execute','host.action.execute','execution-target',?,'human',1,'active','now','now')`, request.HostID); err != nil {
				t.Fatal(err)
			}
			if _, err = f.s.conn.ExecContext(f.ctx, `INSERT INTO effective_authorization_grants VALUES('role-ack','operator-a','control-plane-admin','acknowledge','plan.acknowledge','plan-target',?,'human',1,'active','now','now')`, request.HostID); err != nil {
				t.Fatal(err)
			}
			repo := NewRunRepository(f.s)
			repo.roleGates = gates
			_, err = f.s.executeAuditIntent(f.ctx, discoveryIntent(f.attr, "role.reservation-tested", request.HostID, hostaction.Digest(mode), hostaction.Digest(p)), false, func(ctx context.Context, tx *sql.Tx) error {
				switch mode {
				case "changed-identity":
					_, err = tx.ExecContext(ctx, `UPDATE managed_hosts SET identity_digest=? WHERE host_id=?`, hostaction.Digest("changed identity"), request.HostID)
				case "revoked-read":
					_, err = tx.ExecContext(ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE capability='host.read'`)
				case "revoked-execute":
					_, err = tx.ExecContext(ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE capability='host.action.execute'`)
				case "revoked-ack":
					_, err = tx.ExecContext(ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE capability='plan.acknowledge'`)
				}
				if err != nil {
					return err
				}
				return repo.validateRoleReservation(context.Background(), tx, p, runID, &snapshot)
			})
			if mode == "first-host-role" {
				if err != nil {
					t.Fatal("first role reservation required prior role admission", err)
				}
			} else if err == nil {
				t.Fatal("writer transaction accepted stale proof/current authority", mode)
			}
		})
	}
}

func TestHostRunReadContextUsesDurableActor(t *testing.T) {
	f, _, request := actionDraftFixture(t)
	var runID string
	if err := f.s.conn.QueryRowContext(f.ctx, `SELECT run_id FROM plan_run_steps LIMIT 1`).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	bound, err := f.s.HostRunReadContext(context.Background(), runID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewGateRepository(f.s).ResolveHostAdmission(bound, request.HostID); err != nil {
		t.Fatal("detached actor lost current read authority", err)
	}
	if _, err = f.s.HostRunReadContext(f.ctx, "unknown-run"); err == nil {
		t.Fatal("request principal substituted for missing durable actor")
	}
	if _, err = f.s.conn.ExecContext(f.ctx, `UPDATE effective_authorization_principals SET status='revoked' WHERE principal_id='operator-a'`); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.HostRunReadContext(f.ctx, runID); err == nil {
		t.Fatal("revoked durable actor reused authenticated request")
	}
}
