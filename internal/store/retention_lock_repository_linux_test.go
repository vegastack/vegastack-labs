//go:build linux

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func retentionLockActivationFixture(t *testing.T, authority *Store) LocalRetentionLockActivationRequest {
	t.Helper()
	catalog := LocalRetentionLockCatalog{Schema: "vegastack-labs.dev/local-retention-lock-catalog", SchemaVersion: "1.0.0",
		RepositoryID: backupidentity.StandardRepository, RepositoryClass: "standard", SourceCoverageDigest: LocalPromiseSourceCoverageDigest(),
		RecoveryEpoch: 0, Revision: 2, Complete: true, Locks: []LocalRetentionLock{}}
	_, digest, err := CanonicalLocalRetentionLockCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	draft := validDeclarationStoreRequest()
	draft.Document.DeclarationType = "backup.retention-locks"
	draft.Document.Operations[0].OperationType = "backup.retention-locks.activate"
	draft.Document.Operations[0].AdapterID = "core.retention-locks"
	draft.Document.Operations[0].TargetID = catalog.RepositoryID
	draft.Document.Operations[0].InputDigest = digest
	draft.Document.Operations[0].ArtifactDigest = catalog.SourceCoverageDigest
	draft.Document.ContentDigest = declarationContentDigest(draft.Document, draft.ReasonDigest)
	created, err := NewDeclarationRepository(authority).CreateRevision(context.Background(), draft)
	if err != nil {
		t.Fatal(err)
	}
	commit := validPlanStoreRequest(created.Document)
	commit.Plan.Risk, commit.Plan.AuthorizationBranch = "destructive", "human"
	commit.Plan.Binding.TargetDigest, err = localRepositoryPlanTargetDigest(catalog.RepositoryID)
	if err != nil {
		t.Fatal(err)
	}
	commit.Plan.Operations[0].OperationType = "backup.retention-locks.activate"
	commit.Plan.Operations[0].AdapterID = "core.retention-locks"
	commit.Plan.Operations[0].TargetID = catalog.RepositoryID
	commit.Plan.Operations[0].InputDigest = digest
	commit.Plan.Operations[0].ArtifactDigest = catalog.SourceCoverageDigest
	commit.Plan.PlanID, commit.Plan.PlanDigest = "", ""
	preimage, err := json.Marshal(commit.Plan)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(preimage)
	commit.Plan.PlanDigest = "sha256:" + hex.EncodeToString(sum[:])
	commit.Plan.PlanID = "plan-" + hex.EncodeToString(sum[:16])
	commit.CanonicalBytes, err = json.Marshal(commit.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPlanRepository(authority).CommitDeclarationAndPlan(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	request := LocalRetentionLockActivationRequest{Catalog: catalog, PlanID: commit.Plan.PlanID, PlanDigest: commit.Plan.PlanDigest,
		RunID: "run-locks", StepID: "step-locks", ExecutorLeaseID: "exec-locks", AcknowledgementID: "ack-locks", HumanID: "principal-test-1",
		Expected: RevisionToken{StateRevision: 2, RecoveryEpoch: 0}, Attribution: validDeclarationStoreRequest().Attribution}
	return request
}

func seedRetentionLockRun(t *testing.T, authority *Store, request LocalRetentionLockActivationRequest) {
	t.Helper()
	ctx := context.Background()
	stamp := authority.config.Clock().UTC().Format(time.RFC3339)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO acknowledgement_requests(acknowledgement_id,plan_id,plan_digest,target_digest,reason_digest,human_id,authority_id,nonce_digest,state_revision,recovery_epoch,expires_at,status,request_bytes,pending_bytes,created_at,decided_at,consumed_at) VALUES(?,?,?,?,?,?, 'infrastructure-admin',?,?,?,'2026-09-12T19:00:00Z','approved',X'01',X'01',?,?,?)`,
			[]any{request.AcknowledgementID, request.PlanID, request.PlanDigest, testDigest, testDigest, request.HumanID, "sha256:" + strings.Repeat("e", 64), request.Expected.StateRevision, request.Expected.RecoveryEpoch, stamp, stamp, stamp}},
		{`INSERT INTO acknowledgement_proofs(acknowledgement_id,proof_digest,status,canonical_bytes,received_at) VALUES(?,?,'approved',X'01',?)`,
			[]any{request.AcknowledgementID, "sha256:" + strings.Repeat("d", 64), stamp}},
		{`INSERT INTO plan_runs(run_id,plan_id,plan_digest,authorization_decision_id,acknowledgement_id,policy_version,executor_mode,executor_id,executor_binding_digest,status,cancellation_requested,rollback_status,verification_status,changed,state_revision,recovery_epoch,submit_key_digest,request_digest,canonical_bytes,created_at,updated_at) VALUES(?,?,?,'decision-locks',?,'1.0.0','central','central',?,'running',0,'not-requested','pending',0,?,?,?, ?,X'01',?,?)`,
			[]any{request.RunID, request.PlanID, request.PlanDigest, request.AcknowledgementID, testDigest, request.Expected.StateRevision, request.Expected.RecoveryEpoch, "sha256:" + strings.Repeat("c", 64), "sha256:" + strings.Repeat("b", 64), stamp, stamp}},
		{`INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,active_lease_id,started_at) VALUES(?,?,1,'op-locks','backup.retention-locks.activate','core.retention-locks','central',?,?,?,0,'running','intent-recorded',?,?)`,
			[]any{request.StepID, request.RunID, request.Catalog.RepositoryID, catalogDigestForTest(t, request.Catalog), request.Catalog.SourceCoverageDigest, request.ExecutorLeaseID, stamp}},
		{`INSERT INTO target_execution_leases(lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes) VALUES(?,?,?,?,?,?,?, ?,?,?,?,'active',X'01')`,
			[]any{request.ExecutorLeaseID, request.RunID, request.StepID, request.Catalog.RepositoryID, testDigest, "sha256:" + strings.Repeat("a", 64), request.Expected.RecoveryEpoch, stamp, stamp, "2026-09-12T18:30:10Z", "2026-09-12T18:30:10Z"}},
	}
	for _, statement := range statements {
		if _, err := authority.conn.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed exact human run: %v", err)
		}
	}
}

func catalogDigestForTest(t *testing.T, catalog LocalRetentionLockCatalog) string {
	t.Helper()
	_, digest, err := CanonicalLocalRetentionLockCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestLocalRetentionLockActivationRequiresExactHumanRunAndCompletedProof(t *testing.T) {
	ctx := context.Background()
	authority := openRetirementTestStore(t)
	request := retentionLockActivationFixture(t, authority)
	repository := NewLocalRetirementRepository(authority)
	if _, err := repository.ActivateLocalRetentionLockCatalog(ctx, request); err == nil {
		t.Fatal("unacknowledged catalog activated")
	}
	seedRetentionLockRun(t, authority, request)
	wrongHuman := request
	wrongHuman.HumanID = "other-human"
	if _, err := repository.ActivateLocalRetentionLockCatalog(ctx, wrongHuman); err == nil {
		t.Fatal("wrong human activated catalog")
	}
	activationID, err := repository.ActivateLocalRetentionLockCatalog(ctx, request)
	if err != nil || activationID == "" {
		t.Fatalf("exact human activation: %q %v", activationID, err)
	}
	if _, err := repository.CurrentAppliedLocalRetentionLocks(ctx, "standard", 0); Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("running step exposed catalog before verified completion: %v", err)
	}
	if _, err := authority.conn.ExecContext(ctx, `UPDATE plan_run_steps SET status='succeeded',effect_state='verified' WHERE step_id=?`, request.StepID); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.conn.ExecContext(ctx, `UPDATE plan_runs SET status='succeeded' WHERE run_id=?`, request.RunID); err != nil {
		t.Fatal(err)
	}
	applied, err := repository.CurrentAppliedLocalRetentionLocks(ctx, "standard", 0)
	if err != nil || applied.ActivationID != activationID || applied.CatalogDigest != catalogDigestForTest(t, request.Catalog) || !applied.Catalog.Complete {
		t.Fatalf("completed applied catalog: %#v %v", applied, err)
	}
	// A later corrupt generation must deny retirement instead of silently
	// falling back to the older, valid activation.
	if _, err := authority.conn.ExecContext(ctx, `INSERT INTO backup_retention_lock_catalog_activations(
		activation_id,repository_id,repository_class,catalog_digest,source_coverage_digest,canonical_json,
		declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,acknowledgement_id,
		human_id,state_revision,recovery_epoch,activated_at)
		SELECT 'lock-catalog-tampered',repository_id,repository_class,?,source_coverage_digest,canonical_json,
		declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,acknowledgement_id,
		human_id,state_revision,recovery_epoch,activated_at
		FROM backup_retention_lock_catalog_activations WHERE activation_id=?`, testDigest, activationID); err != nil {
		t.Fatalf("seed later corrupt catalog: %v", err)
	}
	if _, err := repository.CurrentAppliedLocalRetentionLocks(ctx, "standard", 0); Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("later invalid catalog fell back to prior applied generation: %v", err)
	}
}
