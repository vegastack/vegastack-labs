//go:build linux

package store

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
)

func serviceRuntimeFixture(t *testing.T) (*registrationStoreFixture, *ServiceRepository) {
	t.Helper()
	f, r := newServiceCatalogFixture(t)
	var planID, runID string
	if e := f.s.conn.QueryRowContext(f.ctx, `SELECT plan_id,run_id FROM plan_runs LIMIT 1`).Scan(&planID, &runID); e != nil {
		t.Fatal(e)
	}
	policy := f.s.config.ServiceImportPolicies[0]
	record := generated.ServiceRecord{Schema: generated.SchemaIDServiceRecord, SchemaVersion: "1.0.0", Definition: policy.Definition, Revision: 1, RegistrationStatus: "registered", HostAdmission: "not-verified", RegisteredAt: "2026-10-26T00:00:00Z"}
	raw, _ := json.Marshal(record)
	if _, e := f.s.conn.ExecContext(f.ctx, `INSERT INTO service_catalog VALUES(?,?,?,?,?,?,?)`, record.Definition.ServiceID, policy.ResourceKeyDigest, raw, servicecatalog.Digest(record), serviceTestDigest, planID, runID); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = f.s.Close() })
	return f, r
}
func TestServiceRuntimeTargetBindsAcceptedObservation(t *testing.T) {
	f, r := serviceRuntimeFixture(t)
	got, e := r.RuntimeTarget(f.ctx, "service-a")
	if e != nil {
		t.Fatal(e)
	}
	target := discoveryFixtureTarget(t)
	if got.HostID != "synthetic-host" || got.HostIdentityDigest != f.request.Confirmation.IdentityDigest || got.Address != target.Address || got.User != target.User || got.HostKey == "" || got.Port != uint16(target.Port) || got.TargetRevision != 1 || got.TargetDigest != f.request.Confirmation.TargetDigest || got.ExpectedMachineIDDigest != hostdiscovery.Digest("synthetic-machine") || got.StateRevision < 1 || got.RecoveryEpoch != 0 {
		t.Fatalf("incorrect runtime binding: %+v", got)
	}
	// The run's own journal can advance global state; connection identity remains stable.
	if _, e = f.s.conn.ExecContext(f.ctx, `UPDATE system_meta SET state_revision=state_revision+1 WHERE id=1`); e != nil {
		t.Fatal(e)
	}
	next, e := r.RuntimeTarget(f.ctx, "service-a")
	if e != nil {
		t.Fatal(e)
	}
	if next.StateRevision <= got.StateRevision {
		t.Fatal("revision not current")
	}
	next.StateRevision = got.StateRevision
	if next != got {
		t.Fatal("unrelated journal advancement changed binding")
	}
}
func TestServiceRuntimeTargetDeniesBeforeReturningConnection(t *testing.T) {
	for _, mode := range []string{"excluded-host", "excluded-target", "revoked-read", "disabled-owner", "epoch", "revoked-target", "unscoped", "policy"} {
		t.Run(mode, func(t *testing.T) {
			f, r := serviceRuntimeFixture(t)
			ctx := f.ctx
			exec := func(q string, args ...any) {
				t.Helper()
				if _, e := f.s.conn.ExecContext(f.ctx, q, args...); e != nil {
					t.Fatal(e)
				}
			}
			switch mode {
			case "excluded-host":
				f.s.config.NetworkConnectExcludedHostIDs = []string{"synthetic-host"}
			case "excluded-target":
				f.s.config.NetworkConnectExcludedHostIDs = []string{"candidate-a"}
			case "revoked-read":
				exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='service-read'`)
			case "disabled-owner":
				exec(`UPDATE effective_authorization_principals SET status='suspended' WHERE principal_id=?`, f.s.config.ServiceImportPolicies[0].Definition.OwnerID)
			case "epoch":
				exec(`UPDATE system_meta SET recovery_epoch=recovery_epoch+1 WHERE id=1`)
			case "revoked-target":
				exec(`INSERT INTO host_discovery_targets VALUES('candidate-a',2,'fixture-target','revoked','fixture-plan',0)`)
			case "unscoped":
				ctx = context.Background()
			case "policy":
				f.s.config.ServiceImportPolicies = nil
			}
			got, e := r.RuntimeTarget(ctx, "service-a")
			if e == nil || got != (ServiceRuntimeTarget{}) {
				t.Fatalf("connection leaked: %+v %v", got, e)
			}
		})
	}
}
