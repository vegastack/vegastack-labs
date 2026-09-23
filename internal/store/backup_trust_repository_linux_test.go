package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func backupTrustDraftFixture() generated.BackupTrustSourceDraftRequest {
	return generated.BackupTrustSourceDraftRequest{
		Schema: generated.SchemaIDBackupTrustSourceDraftRequest, SchemaVersion: "1.0.0",
		SourceID: "source-config-a", DependencyID: "config-a", DependencyKind: "config",
		ArtifactID: "artifact-config-a", ArtifactDigest: "sha256:" + strings.Repeat("a", 64),
		BundleDigest: "sha256:" + strings.Repeat("b", 64), TrustedRootReferenceID: "root-a",
		TrustRootDigest: "sha256:" + strings.Repeat("c", 64),
		SignerIdentity:  "https://example.invalid/vegastack/synthetic-release",
		SignerIssuer:    "https://issuer.example.invalid", Revision: 1, RecoveryEpoch: 0,
		ExpectedStateRevision: 0, IdempotencyKey: "trust-source-a",
	}
}

func TestBackupTrustDraftCannotActivateItself(t *testing.T) {
	repository := NewBackupRepository(openTestStore(t))
	attribution := audit.Attribution{AuthenticatedPrincipalID: "human-a", AuthenticatedPrincipalMethod: "local-os-peer"}
	draft, err := repository.CreateBackupTrustSourceDraft(context.Background(), backupTrustDraftFixture(), attribution)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetCurrentBackupTrustSource(context.Background(), draft.SourceID, draft.Revision, draft.StateRevision, draft.RecoveryEpoch); err == nil {
		t.Fatal("inert trust draft became current")
	}
	var got int
	if err := repository.store.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM backup_trust_source_bindings`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Fatalf("draft created %d current bindings", got)
	}
}

func TestBackupTrustSourceRequiresExactBindingAndRevocationWins(t *testing.T) {
	ctx := context.Background()
	repository := NewBackupRepository(openTestStore(t))
	attribution := audit.Attribution{AuthenticatedPrincipalID: "human-a", AuthenticatedPrincipalMethod: "local-os-peer"}
	draft, err := repository.CreateBackupTrustSourceDraft(ctx, backupTrustDraftFixture(), attribution)
	if err != nil {
		t.Fatal(err)
	}
	apply := BackupTrustSourceApplyRequest{
		BindingID: "binding-a", SourceID: draft.SourceID, SourceRevision: draft.Revision, Status: "current",
		PlanID: "plan-a", PlanDigest: "sha256:" + strings.Repeat("d", 64), RunID: "run-a", StepID: "step-a",
		LeaseID: "lease-a", DeclarationID: "declaration-a", DeclarationRevision: 1,
		Expected: RevisionToken{StateRevision: draft.StateRevision, RecoveryEpoch: draft.RecoveryEpoch}, Attribution: attribution,
	}
	if _, err := repository.ApplyBackupTrustSource(ctx, apply); Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("fabricated execution binding was accepted: %v", err)
	}
	seedBackupTrustExactStep(t, repository, apply, draft, "backup.trust-source.current")
	current, err := repository.ApplyBackupTrustSource(ctx, apply)
	if err != nil || current.DependencyID != "config-a" || current.ArtifactDigest != backupTrustDraftFixture().ArtifactDigest {
		t.Fatalf("apply current = %#v, %v", current, err)
	}
	if _, err := repository.GetCurrentBackupTrustSourceForDependency(ctx, "config-a", "config", draft.StateRevision+1, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetCurrentBackupTrustSourceForDependency(ctx, "config-a", "config", draft.StateRevision, 0); err == nil {
		t.Fatal("stale state resolved current source")
	}
	apply.BindingID, apply.Status, apply.Expected.StateRevision = "binding-revoke-a", "revoked", draft.StateRevision+1
	apply.PlanID, apply.RunID, apply.StepID, apply.LeaseID, apply.DeclarationID = "plan-revoke-a", "run-revoke-a", "step-revoke-a", "lease-revoke-a", "declaration-revoke-a"
	seedBackupTrustExactStep(t, repository, apply, draft, "backup.trust-source.revoke")
	if _, err := repository.ApplyBackupTrustSource(ctx, apply); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetCurrentBackupTrustSourceForDependency(ctx, "config-a", "config", draft.StateRevision+2, 0); err == nil {
		t.Fatal("revoked source remained current")
	}
}

func seedBackupTrustExactStep(t *testing.T, repository *BackupRepository, request BackupTrustSourceApplyRequest, draft BackupTrustSourceDraft, operationType string) {
	t.Helper()
	now := repository.store.config.Clock().UTC().Truncate(time.Second)
	created, expires := now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339)
	digest := "sha256:" + strings.Repeat("e", 64)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO declaration_revisions(declaration_id,declaration_revision,declaration_type,state_revision,recovery_epoch,content_digest,reason_digest,status,canonical_bytes,created_at,created_by,agent_session_id) VALUES(?,?,'backup-trust-source',?,?,?,?,'committed',X'7B7D',?,'human-a','session-a')`, []any{request.DeclarationID, request.DeclarationRevision, request.Expected.StateRevision, request.Expected.RecoveryEpoch, digest, digest, created}},
		{`INSERT INTO immutable_plans(plan_id,plan_digest,declaration_id,declaration_revision,state_revision,recovery_epoch,observation_fingerprint,idempotency_key_digest,request_digest,canonical_bytes,readable_plan,readable_digest,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,X'7B7D','synthetic',?,?,?)`, []any{request.PlanID, request.PlanDigest, request.DeclarationID, request.DeclarationRevision, request.Expected.StateRevision, request.Expected.RecoveryEpoch, digest, digest, digest, digest, created, expires}},
		{`INSERT INTO plan_runs(run_id,plan_id,plan_digest,authorization_decision_id,acknowledgement_id,policy_version,executor_mode,executor_id,executor_binding_digest,status,cancellation_requested,rollback_status,verification_status,verification_digest,changed,state_revision,recovery_epoch,submit_key_digest,request_digest,canonical_bytes,created_at,updated_at) VALUES(?,?,?,'decision-a',NULL,'1.0.0','central','executor-central',?,'running',0,'not-requested','pending',NULL,0,?,?,?, ?,X'7B7D',?,?)`, []any{request.RunID, request.PlanID, request.PlanDigest, digest, request.Expected.StateRevision, request.Expected.RecoveryEpoch, digest, digest, created, created}},
		{`INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,active_lease_id,result_digest,started_at,finished_at) VALUES(?,?,1,'operation-a',?,'core.backup-trust','executor-central',?,?,?,1,'running','intent-recorded',?,NULL,?,NULL)`, []any{request.StepID, request.RunID, operationType, draft.SourceID, draft.Digest, draft.Digest, request.LeaseID, created}},
		{`INSERT INTO target_execution_leases(lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes,lease_kind,last_renewed_at,renewal_count) VALUES(?,?,?,?,?,?,?, ?,?,?,?,'active',X'7B7D','central',NULL,0)`, []any{request.LeaseID, request.RunID, request.StepID, draft.SourceID, digest, digest, request.Expected.RecoveryEpoch, created, created, expires, expires}},
	}
	for index, statement := range statements {
		if _, err := repository.store.conn.ExecContext(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(fmt.Errorf("seed backup trust statement %d: %w", index, err))
		}
	}
}
