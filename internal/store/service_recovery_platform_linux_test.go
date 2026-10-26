//go:build linux

package store

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicerecovery"
	"testing"
)

func TestPlatformRecoveryUsesManagedIdentityWithoutFakeApplication(t *testing.T) {
	f, _ := newServiceCatalogFixture(t)
	defer f.s.Close()
	hostID := f.request.HostID
	p := servicerecovery.Policy{Binding: generated.ServiceRecoveryBinding{Schema: generated.SchemaIDServiceRecoveryBinding, SchemaVersion: "1.0.0", PolicyID: "platform-backup", ServiceID: "platform-coolify", ConfigurationDigest: serviceTestDigest, DataClass: "platform", ConsistencyProcedureID: servicerecovery.ConsistencyProcedureID, SourceHostID: hostID, TargetHostID: "target-host"}, PlatformOwnerID: "operator-a", TargetServiceID: "platform-target"}
	f.s.config.ServiceRecoveryPolicies = []servicerecovery.Policy{p}
	if _, e := f.s.conn.ExecContext(f.ctx, `INSERT INTO effective_authorization_grants VALUES('platform-author','operator-a','control-plane-admin','author','service.recovery.prepare','service','platform-coolify',NULL,1,'active','now','now')`); e != nil {
		t.Fatal(e)
	}
	r := NewServiceRecoveryRepository(f.s)
	rev, e := NewPlanRepository(f.s).CurrentRevision(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	q, e := r.Prepare(f.ctx, generated.ServiceRecoveryDraftRequest{Schema: generated.SchemaIDServiceRecoveryDraftRequest, SchemaVersion: "1.0.0", ServiceID: p.Binding.ServiceID, PolicyID: p.Binding.PolicyID, Action: "backup", ExpectedStateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch, IdempotencyKey: "platform-a", ReasonDigest: serviceTestDigest})
	if e != nil {
		t.Fatal(e)
	}
	if q.Definition.EnvironmentID != "platform" || q.Definition.HostID != hostID || q.Definition.HostIdentityDigest != f.request.Confirmation.IdentityDigest {
		t.Fatalf("wrong managed platform identity: %+v", q.Definition)
	}
	var n int
	if f.s.conn.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM service_catalog`).Scan(&n) != nil || n != 0 {
		t.Fatal("platform fabricated application registration")
	}
	if _, e = r.HostRuntimeTarget(f.ctx, hostID, q.Definition.HostIdentityDigest); e != nil {
		t.Fatal("managed platform transport not resolved", e)
	}
	f.s.config.NetworkConnectExcludedHostIDs = []string{hostID}
	if _, e = r.HostRuntimeTarget(f.ctx, hostID, q.Definition.HostIdentityDigest); Code(e) != generated.ErrorCodeAuthorizationDenied {
		t.Fatal("protected platform host allowed", e)
	}
}
