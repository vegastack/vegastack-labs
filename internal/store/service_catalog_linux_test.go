//go:build linux

package store

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"testing"
)

func newServiceCatalogFixture(t *testing.T) (*registrationStoreFixture, *ServiceRepository) {
	t.Helper()
	f := newRegistrationStoreFixture(t)
	draft := f.Stage(t)
	if _, err := f.repo.Apply(f.ctx, f.bind(t, draft)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.conn.ExecContext(f.ctx, `INSERT INTO read_principals VALUES('operator-a','active',1,'now','now')`); err != nil {
		t.Fatal(err)
	}
	p := servicePolicyFixture()
	p.Definition.HostIdentityDigest = f.request.Confirmation.IdentityDigest
	f.s.config.ServiceImportPolicies = []servicecatalog.Policy{p}
	if _, err := f.s.conn.ExecContext(f.ctx, `INSERT INTO effective_authorization_grants VALUES('service-author','operator-a','maintainer','author','service.import.prepare','service','service-a',NULL,1,'active','now','now'),('service-read','operator-a','reader','read','service.read','service','service-a',NULL,1,'active','now','now')`); err != nil {
		t.Fatal(err)
	}
	return f, NewServiceRepository(f.s)
}
func TestServiceImportPreparationAndStageRemainInert(t *testing.T) {
	f, r := newServiceCatalogFixture(t)
	defer f.s.Close()
	rev, err := NewPlanRepository(f.s).CurrentRevision(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	draft := generated.ServiceImportDraftRequest{Schema: generated.SchemaIDServiceImportDraftRequest, SchemaVersion: "1.0.0", ServiceID: "service-a", BindingID: "binding-a", ExpectedStateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch, IdempotencyKey: "import-a", ReasonDigest: serviceTestDigest}
	in, err := r.Prepare(f.ctx, draft)
	if err != nil {
		t.Fatal(err)
	}
	if in.ObservationDigest != "" {
		t.Fatal("preparation fabricated observation")
	}
	if _, err = r.Stage(f.ctx, in); err == nil {
		t.Fatal("unobserved draft staged")
	}
	in.ObservationDigest = serviceTestDigest
	staged, err := r.Stage(f.ctx, in)
	if err != nil || staged.ServiceImport == nil {
		t.Fatal(err)
	}
	var count int
	if err = f.s.conn.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM service_catalog`).Scan(&count); err != nil || count != 0 {
		t.Fatal("stage registered service", err, count)
	}
	if _, err = r.Get(f.ctx, "service-a"); err == nil {
		t.Fatal("inert service exists")
	}
	f.s.config.NetworkConnectExcludedHostIDs = []string{"synthetic-host"}
	if _, err = r.Prepare(f.ctx, draft); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatal("excluded host accepted", err)
	}
}

func TestServiceCatalogReadsOnlyExactCurrentScope(t *testing.T) {
	f, r := newServiceCatalogFixture(t)
	defer f.s.Close()
	var planID, runID string
	if err := f.s.conn.QueryRowContext(f.ctx, `SELECT plan_id,run_id FROM plan_runs LIMIT 1`).Scan(&planID, &runID); err != nil {
		t.Fatal(err)
	}
	policy := f.s.config.ServiceImportPolicies[0]
	record := generated.ServiceRecord{Schema: generated.SchemaIDServiceRecord, SchemaVersion: "1.0.0", Definition: policy.Definition, Revision: 1, RegistrationStatus: "registered", HostAdmission: "not-verified", RegisteredAt: "2026-10-01T00:00:00Z"}
	raw, _ := json.Marshal(record)
	if _, err := f.s.conn.ExecContext(f.ctx, `INSERT INTO service_catalog VALUES(?,?,?,?,?,?,?)`, record.Definition.ServiceID, policy.ResourceKeyDigest, raw, servicecatalog.Digest(record), serviceTestDigest, planID, runID); err != nil {
		t.Fatal(err)
	}
	// Foreign keys and one record per approved run prevent fabricated imports.
	if _, err := f.s.conn.ExecContext(f.ctx, `INSERT INTO service_catalog VALUES('private-service',?,X'7B7D',?,?,?,'private-run')`, servicecatalog.Digest("private-resource"), serviceTestDigest, serviceTestDigest, planID); err == nil {
		t.Fatal("missing run foreign key accepted")
	}
	// A unique run is a durability bound, so a second registered record cannot
	// masquerade as the first approved effect.
	if _, err := f.s.conn.ExecContext(f.ctx, `INSERT INTO service_catalog VALUES('private-service',?,X'7B7D',?,?,?,?)`, servicecatalog.Digest("private-resource"), serviceTestDigest, serviceTestDigest, planID, runID); err == nil {
		t.Fatal("same run registered a second service")
	}
	if _, err := f.s.conn.ExecContext(f.ctx, `INSERT INTO plan_runs SELECT 'private-run',plan_id,plan_digest,authorization_decision_id,NULL,policy_version,executor_mode,executor_id,executor_binding_digest,status,cancellation_requested,rollback_status,verification_status,verification_digest,changed,state_revision,recovery_epoch,?,request_digest,canonical_bytes,created_at,updated_at FROM plan_runs WHERE run_id=?`, servicecatalog.Digest("private-submit"), runID); err != nil {
		t.Fatal(err)
	}
	// Deliberately corrupt private bytes fail if the list reads them. The caller
	// holds only the service-a grant, so the SQL must exclude this record.
	if _, err := f.s.conn.ExecContext(f.ctx, `INSERT INTO service_catalog VALUES('private-service',?,X'7B7D',?,?,?,'private-run')`, servicecatalog.Digest("private-resource"), serviceTestDigest, serviceTestDigest, planID); err != nil {
		t.Fatal(err)
	}
	list, err := r.List(f.ctx, "", 1)
	if err != nil || len(list.Services) != 1 || list.Services[0].Definition.ServiceID != "service-a" {
		t.Fatal(list, err)
	}
	next, err := r.List(f.ctx, "service-a", 1)
	if err != nil || len(next.Services) != 0 {
		t.Fatal(next, err)
	}
	if _, err = r.Get(f.ctx, "private-service"); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatal("ungranted record existence leaked", err)
	}
	if _, err := f.s.conn.ExecContext(f.ctx, `UPDATE service_catalog SET digest=? WHERE service_id='service-a'`, serviceTestDigest); err == nil {
		t.Fatal("registration mutable")
	}
	if _, err := f.s.conn.ExecContext(f.ctx, `DELETE FROM service_catalog WHERE service_id='service-a'`); err == nil {
		t.Fatal("registration deletable")
	}
	if _, err := f.s.conn.ExecContext(f.ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='service-read'`); err != nil {
		t.Fatal(err)
	}
	if _, err = r.List(f.ctx, "", 1); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatal("revoked list scope accepted", err)
	}
	if _, err = r.Get(f.ctx, "service-a"); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatal("revoked detail scope accepted", err)
	}
}
