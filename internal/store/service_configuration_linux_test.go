//go:build linux

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"testing"
	"time"
)

func configurationFixture() generated.ServiceConfiguration {
	return generated.ServiceConfiguration{Schema: generated.SchemaIDServiceConfiguration, SchemaVersion: "1.0.0", EnvironmentClass: "development", CPUQuotaPercent: 100, MemoryBytes: 268435456, StorageBytes: 1048576, Port: 8080, Exposure: "private", HealthPath: "/ready", HealthExpectedStatus: 200, HealthIntervalSeconds: 10, HealthTimeoutSeconds: 2, HealthRetries: 3, DataClass: "stateless", Migration: "none", Rollback: "previous-artifact", SecretReferenceIDs: []string{}}
}
func TestServicePlacementRejectsUnknownAndOvercommittedCapacity(t *testing.T) {
	f, r, in := newDeploymentFixture(t)
	defer f.s.Close()
	config := configurationFixture()
	in.Configuration = &config
	f.s.config.ServiceDeploymentPolicies[0].Configuration = &config
	if _, e := r.Stage(f.ctx, in); e == nil {
		t.Fatal("configuration without actual capacity accepted")
	}
	var planID, runID string
	if e := f.s.conn.QueryRowContext(f.ctx, `SELECT plan_id,run_id FROM plan_runs LIMIT 1`).Scan(&planID, &runID); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.conn.ExecContext(f.ctx, `INSERT INTO plan_runs SELECT 'capacity-second-run',plan_id,plan_digest,authorization_decision_id,NULL,policy_version,executor_mode,executor_id,executor_binding_digest,status,cancellation_requested,rollback_status,verification_status,verification_digest,changed,state_revision,recovery_epoch,?,request_digest,canonical_bytes,created_at,updated_at FROM plan_runs WHERE run_id=?`, servicecatalog.Digest("capacity-second"), runID); e != nil {
		t.Fatal(e)
	}
	record := generated.ServiceRecord{Schema: generated.SchemaIDServiceRecord, SchemaVersion: "1.0.0", Definition: in.Definition, Revision: 1, RegistrationStatus: "registered", HostAdmission: "not-verified", RegisteredAt: "2026-10-26T00:00:00Z"}
	record.Definition.ServiceID = "service-b"
	raw, _ := json.Marshal(record)
	if _, e := f.s.conn.ExecContext(f.ctx, `INSERT INTO service_catalog VALUES('service-b',?,?,?,?,?,'capacity-second-run')`, servicecatalog.Digest("capacity-second-resource"), raw, servicecatalog.Digest(record), serviceTestDigest, planID); e != nil {
		t.Fatal(e)
	}
	now := f.s.config.Clock().UTC()
	capacity := generated.ServiceCapacity{Schema: generated.SchemaIDServiceCapacity, SchemaVersion: "1.0.0", HostID: in.Definition.HostID, HostIdentityDigest: in.Definition.HostIdentityDigest, TargetDigest: serviceTestDigest, CPUQuotaPercent: 150, MemoryBytes: 1 << 30, StorageBytes: 1 << 30, ObservedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339), RecoveryEpoch: in.RecoveryEpoch}
	in.Capacity = &capacity
	// Numbers supplied by a caller without a persisted exact-machine observation
	// cannot enter an otherwise correctly scoped deployment declaration.
	if _, e := r.Stage(f.ctx, in); e == nil {
		t.Fatal("unrecorded numeric capacity accepted")
	}
	tx, e := f.s.conn.BeginTx(context.Background(), nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = reserveServiceCapacity(f.ctx, tx, in, planID); e != nil {
		_ = tx.Rollback()
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	// A second transaction sees the durable allocation before any provider write,
	// so two independently planned services cannot both claim the same CPU.
	second := in
	second.Definition.ServiceID = "service-b"
	tx, e = f.s.conn.BeginTx(context.Background(), nil)
	if e != nil {
		t.Fatal(e)
	}
	e = reserveServiceCapacity(f.ctx, tx, second, planID)
	_ = tx.Rollback()
	if e == nil {
		t.Fatal("overcommitted second service reserved")
	}
	// A failed or unknown deployment keeps its conservative reservation.
	var cpu int64
	if e = f.s.conn.QueryRowContext(f.ctx, `SELECT cpu_percent FROM service_capacity_reservations WHERE service_id='service-a'`).Scan(&cpu); e != nil || cpu != 100 {
		t.Fatal(cpu, e)
	}
}

func TestConfiguredDeploymentReservesBeforeAttemptAndRetainsPartial(t *testing.T) {
	f, r, in := newDeploymentFixture(t)
	defer f.s.Close()
	config := configurationFixture()
	in.Configuration = &config
	f.s.config.ServiceDeploymentPolicies[0].Configuration = &config
	var targetID string
	if e := f.s.conn.QueryRowContext(f.ctx, `SELECT target_id FROM managed_hosts WHERE host_id=?`, in.Definition.HostID).Scan(&targetID); e != nil {
		t.Fatal(e)
	}
	target, e := discoveryTarget(func(q string, a ...any) *sql.Row { return f.s.conn.QueryRowContext(f.ctx, q, a...) }, targetID)
	if e != nil {
		t.Fatal(e)
	}
	now := f.s.config.Clock().UTC().Truncate(time.Second)
	capacity := generated.ServiceCapacity{Schema: generated.SchemaIDServiceCapacity, SchemaVersion: "1.0.0", HostID: in.Definition.HostID, HostIdentityDigest: in.Definition.HostIdentityDigest, TargetDigest: target.Digest, CPUQuotaPercent: 150, MemoryBytes: 1 << 30, StorageBytes: 1 << 30, ObservedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339), RecoveryEpoch: in.RecoveryEpoch}
	in.Capacity = &capacity
	if e = r.RecordCapacity(f.ctx, in.Definition.ServiceID, capacity); e != nil {
		t.Fatal(e)
	}
	apply := seedDeploymentExecution(t, f, in)
	if e = r.Begin(f.ctx, apply); e != nil {
		t.Fatal(e)
	}
	var reserved, attempted int
	if e = f.s.conn.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM service_capacity_reservations WHERE service_id=? AND plan_id=?`, in.Definition.ServiceID, apply.PlanID).Scan(&reserved); e != nil {
		t.Fatal(e)
	}
	if e = f.s.conn.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM service_deployment_attempts WHERE plan_id=? AND status='attempted'`, apply.PlanID).Scan(&attempted); e != nil || reserved != 1 || attempted != 1 {
		t.Fatal(reserved, attempted, e)
	}
	if _, e = r.Complete(f.ctx, apply, servicecatalog.DeploymentOutcome{Status: "partial", ProviderStage: "environment_attempted"}); e != nil {
		t.Fatal(e)
	}
	if e = f.s.conn.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM service_capacity_reservations WHERE service_id=?`, in.Definition.ServiceID).Scan(&reserved); e != nil || reserved != 1 {
		t.Fatal("partial released uncertain capacity", reserved, e)
	}
	if e = r.Begin(f.ctx, apply); e == nil {
		t.Fatal("partial configuration attempt replayed")
	}
}

func TestServiceEnvironmentRemovalRequiresExplicitCleanup(t *testing.T) {
	f, _, in := newDeploymentFixture(t)
	defer f.s.Close()
	configuration := configurationFixture()
	configuration.SecretReferenceIDs = []string{"application-key"}
	in.Configuration = &configuration
	in.EnvironmentBindings = []generated.ServiceEnvironmentSecret{{Schema: generated.SchemaIDServiceEnvironmentSecret, SchemaVersion: "1.0.0", Name: "APP_KEY", ReferenceID: "application-key", ExpectedFingerprint: serviceTestDigest}}
	var planID, runID string
	if e := f.s.conn.QueryRowContext(f.ctx, `SELECT plan_id,run_id FROM plan_runs LIMIT 1`).Scan(&planID, &runID); e != nil {
		t.Fatal(e)
	}
	record, e := deploymentRecord(in, ServiceDeploymentApply{PlanID: planID, RunID: runID}, servicecatalog.DeploymentOutcome{Status: "succeeded", ReceiptDigest: serviceTestDigest, RuntimeDigest: serviceTestDigest, RunningDigest: in.Artifact.Digest, Running: true, Healthy: true}, f.s.config.Clock())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(record)
	if _, e = f.s.conn.ExecContext(f.ctx, `INSERT INTO service_deployments(service_id,revision,plan_id,run_id,artifact_digest,recovery_epoch,status,canonical_bytes,digest) VALUES(?,?,?,?,?,?,?,?,?)`, in.Definition.ServiceID, 1, planID, runID, in.Artifact.Digest, in.RecoveryEpoch, "succeeded", raw, servicecatalog.Digest(record)); e != nil {
		t.Fatal(e)
	}
	row := func(q string, a ...any) *sql.Row { return f.s.conn.QueryRowContext(f.ctx, q, a...) }
	removed := in
	removed.EnvironmentBindings = nil
	if e = validateEnvironmentContinuity(row, removed); e == nil {
		t.Fatal("removing tracked environment key silently accepted")
	}
	renamed := in
	renamed.EnvironmentBindings = append([]generated.ServiceEnvironmentSecret(nil), in.EnvironmentBindings...)
	renamed.EnvironmentBindings[0].Name = "OTHER_KEY"
	if e = validateEnvironmentContinuity(row, renamed); e == nil {
		t.Fatal("renaming tracked environment key silently accepted")
	}
	rotated := in
	rotated.EnvironmentBindings = append([]generated.ServiceEnvironmentSecret(nil), in.EnvironmentBindings...)
	rotated.EnvironmentBindings[0].ReferenceID = "rotated-application-key"
	rotated.EnvironmentBindings[0].ExpectedFingerprint = servicecatalog.Digest("rotated-material")
	if e = validateEnvironmentContinuity(row, rotated); e != nil {
		t.Fatal("same-key rotation was rejected", e)
	}
}
