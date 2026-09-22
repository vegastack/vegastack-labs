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

func retirementStageFixture(t *testing.T, authority *Store, risk, branch string) LocalRetirementStageRequest {
	t.Helper()
	request := LocalRetirementStageRequest{RepositoryID: backupidentity.StandardRepository, RepositoryClass: "standard",
		CatalogDigest: testDigest, ExpectedInventoryDigest: testDigest, LockCatalogDigest: testDigest, SourceCoverageDigest: testDigest, LockCatalogSequence: 1,
		Targets:        []LocalRetirementTarget{{PointID: "old-point", SnapshotID: strings.Repeat("a", 64), ManifestDigest: testDigest, InventoryDigest: testDigest, DependencyDigest: testDigest}},
		Survivors:      []LocalRetirementSurvivor{{PointID: "good-point", SnapshotID: strings.Repeat("b", 64), ManifestDigest: testDigest, InventoryDigest: testDigest, DependencyDigest: testDigest, ProofDigest: testDigest}},
		SourceRevision: 2, StateRevision: 2, RecoveryEpoch: 0, MaxWorkObjects: 10, MaxMutationBytes: 1024, MaxRepackBytes: 1024,
		Attribution: validDeclarationStoreRequest().Attribution}
	_, digest, err := canonicalRetirementSelection(request)
	if err != nil {
		t.Fatal(err)
	}
	request.SelectionDigest = digest
	draft := validDeclarationStoreRequest()
	draft.Document.DeclarationType = "backup.retirement"
	draft.Document.Operations[0].OperationType = "backup.local.retire"
	draft.Document.Operations[0].AdapterID = "local.retention"
	draft.Document.Operations[0].TargetID = request.RepositoryID
	draft.Document.Operations[0].InputDigest = digest
	draft.Document.Operations[0].ArtifactDigest = request.ExpectedInventoryDigest
	draft.Document.ContentDigest = declarationContentDigest(draft.Document, draft.ReasonDigest)
	created, err := NewDeclarationRepository(authority).CreateRevision(context.Background(), draft)
	if err != nil {
		t.Fatal(err)
	}
	commit := validPlanStoreRequest(created.Document)
	commit.Plan.Risk, commit.Plan.AuthorizationBranch = risk, branch
	commit.Plan.Binding.TargetDigest, err = localRepositoryPlanTargetDigest(request.RepositoryID)
	if err != nil {
		t.Fatal(err)
	}
	commit.Plan.Operations[0].OperationType = "backup.local.retire"
	commit.Plan.Operations[0].AdapterID = "local.retention"
	commit.Plan.Operations[0].TargetID = request.RepositoryID
	commit.Plan.Operations[0].InputDigest = digest
	commit.Plan.Operations[0].ArtifactDigest = request.ExpectedInventoryDigest
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
	request.PlanID, request.PlanDigest = commit.Plan.PlanID, commit.Plan.PlanDigest
	return request
}

func openRetirementTestStore(t *testing.T) *Store {
	t.Helper()
	config := testConfig(t)
	config.Clock = func() time.Time { return time.Date(2026, 9, 12, 18, 30, 0, 0, time.UTC) }
	authority, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	return authority
}

func TestRetirementDeadlineParsesOffsetBeforeAdmission(t *testing.T) {
	now := time.Date(2026, 9, 12, 18, 30, 0, 0, time.UTC)
	if retirementDeadlineCurrent("2026-09-12T19:00:00+05:30", now) ||
		!retirementDeadlineCurrent("2026-09-12T19:00:00Z", now) ||
		retirementDeadlineCurrent("invalid", now) {
		t.Fatal("retirement deadline compared text instead of absolute time")
	}
}

func TestLocalRetentionLockCatalogRequiresAppliedCompleteness(t *testing.T) {
	authority := openRetirementTestStore(t)
	if _, err := NewLocalRetirementRepository(authority).CurrentAppliedLocalRetentionLocks(context.Background(), "standard", 0); Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("missing applied lock catalog was treated as empty: %v", err)
	}
	base := LocalRetentionLockCatalog{Schema: "vegastack-labs.dev/local-retention-lock-catalog", SchemaVersion: "1.0.0",
		RepositoryID: backupidentity.StandardRepository, RepositoryClass: "standard", RecoveryEpoch: 0, Revision: 1,
		SourceCoverageDigest: LocalPromiseSourceCoverageDigest(), Complete: true, Locks: []LocalRetentionLock{}}
	if _, digest, err := CanonicalLocalRetentionLockCatalog(base); err != nil || !validBackupDigest(digest) {
		t.Fatalf("explicit complete empty declaration invalid: %s %v", digest, err)
	}
	for name, mutate := range map[string]func(*LocalRetentionLockCatalog){
		"missing-assertion": func(c *LocalRetentionLockCatalog) { c.Complete = false },
		"stale-coverage":    func(c *LocalRetentionLockCatalog) { c.SourceCoverageDigest = testDigest },
		"unknown-point-id": func(c *LocalRetentionLockCatalog) {
			c.Locks = []LocalRetentionLock{{PointID: "", ReasonDigest: testDigest}}
		},
		"duplicate-lock": func(c *LocalRetentionLockCatalog) {
			c.Locks = []LocalRetentionLock{{PointID: "point-a", ReasonDigest: testDigest}, {PointID: "point-a", ReasonDigest: testDigest}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if _, _, err := CanonicalLocalRetentionLockCatalog(candidate); err == nil {
				t.Fatal("invalid lock catalog canonicalized")
			}
		})
	}
}

func TestLocalRetirementStageIsInertExactAndAppendOnly(t *testing.T) {
	authority := openRetirementTestStore(t)
	request := retirementStageFixture(t, authority, "destructive", "human")
	repository := NewLocalRetirementRepository(authority)
	intent, err := repository.StageLocalRetirement(context.Background(), request)
	if err != nil || intent.IntentID == "" || intent.Request.SelectionDigest != request.SelectionDigest {
		t.Fatalf("stage intent: %#v %v", intent, err)
	}
	if replay, err := repository.StageLocalRetirement(context.Background(), request); err != nil || replay.IntentID != intent.IntentID {
		t.Fatalf("idempotent replay: %#v %v", replay, err)
	}
	otherActor := request
	otherActor.Attribution.AuthenticatedPrincipalID = "other-human"
	if _, err := repository.StageLocalRetirement(context.Background(), otherActor); err == nil {
		t.Fatal("another human replayed the same plan intent")
	}
	for _, table := range []string{"backup_retirement_leases", "backup_retirement_mutation_attempts", "backup_retirement_successor_generations", "backup_retirement_finalizations"} {
		var count int
		if err := authority.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("staging activated %s: count=%d err=%v", table, count, err)
		}
	}
	if _, err := authority.conn.ExecContext(context.Background(), `UPDATE backup_retirement_intents SET selection_digest=? WHERE intent_id=?`, testDigest, intent.IntentID); err == nil {
		t.Fatal("immutable retirement intent updated")
	}
	if _, err := authority.conn.ExecContext(context.Background(), `DELETE FROM backup_retirement_intents WHERE intent_id=?`, intent.IntentID); err == nil {
		t.Fatal("immutable retirement intent deleted")
	}
}

func TestLocalRetirementStageRejectsStaleOrNonHumanPlan(t *testing.T) {
	for _, test := range []struct{ name, risk, branch string }{
		{"routine", "routine", "human"},
		{"preauthorized", "destructive", "preauthorized"},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := openRetirementTestStore(t)
			request := retirementStageFixture(t, authority, test.risk, test.branch)
			if _, err := NewLocalRetirementRepository(authority).StageLocalRetirement(context.Background(), request); err == nil {
				t.Fatal("non-human destructive plan staged retirement")
			}
		})
	}
	authority := openRetirementTestStore(t)
	request := retirementStageFixture(t, authority, "destructive", "human")
	repository := NewLocalRetirementRepository(authority)
	invalid := request
	invalid.Survivors = append([]LocalRetirementSurvivor(nil), request.Survivors...)
	invalid.Survivors[0].ProofDigest = ""
	if _, err := repository.StageLocalRetirement(context.Background(), invalid); err == nil {
		t.Fatal("unproved survivor staged")
	}
	invalid = request
	invalid.StateRevision--
	if _, err := repository.StageLocalRetirement(context.Background(), invalid); err == nil {
		t.Fatal("stale state revision staged")
	}
	invalid = request
	invalid.PlanID = "plan-forged"
	if _, err := repository.StageLocalRetirement(context.Background(), invalid); err == nil {
		t.Fatal("unstored plan staged")
	}
	var count int
	if err := authority.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM backup_retirement_intents`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("denial wrote intent: %d %v", count, err)
	}
}

func TestLocalRetirementStageRequiresExactPointSets(t *testing.T) {
	authority := openRetirementTestStore(t)
	request := retirementStageFixture(t, authority, "destructive", "human")
	repository := NewLocalRetirementRepository(authority)
	for name, mutate := range map[string]func(*LocalRetirementStageRequest){
		"target-survivor-overlap": func(r *LocalRetirementStageRequest) { r.Targets[0].PointID = r.Survivors[0].PointID },
		"duplicate-snapshot":      func(r *LocalRetirementStageRequest) { r.Targets[0].SnapshotID = r.Survivors[0].SnapshotID },
		"wrong-repository":        func(r *LocalRetirementStageRequest) { r.RepositoryID = "other" },
		"malformed-snapshot":      func(r *LocalRetirementStageRequest) { r.Targets[0].SnapshotID = "short" },
		"missing-proof":           func(r *LocalRetirementStageRequest) { r.Survivors[0].ProofDigest = "" },
		"missing-inventory":       func(r *LocalRetirementStageRequest) { r.Survivors[0].InventoryDigest = "" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := request
			invalid.Targets = append([]LocalRetirementTarget(nil), request.Targets...)
			invalid.Survivors = append([]LocalRetirementSurvivor(nil), request.Survivors...)
			mutate(&invalid)
			_, digest, err := canonicalRetirementSelection(invalid)
			if err == nil {
				invalid.SelectionDigest = digest
			}
			if _, err := repository.StageLocalRetirement(context.Background(), invalid); err == nil {
				t.Fatal("ambiguous point selection staged")
			}
		})
	}
}

func TestUnreconciledRetentionLeaseExcludesBackupWriterAndReader(t *testing.T) {
	ctx := context.Background()
	authority := openRetirementTestStore(t)
	request := retirementStageFixture(t, authority, "destructive", "human")
	intent, err := NewLocalRetirementRepository(authority).StageLocalRetirement(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	stamp := authority.config.Clock().UTC().Format(time.RFC3339)
	// All references are real rows with foreign keys enabled. The retention
	// lease itself is synthetic because the executable claim path is still
	// deliberately absent; this tests the existing writer's fence.
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO acknowledgement_requests(acknowledgement_id,plan_id,plan_digest,target_digest,reason_digest,human_id,authority_id,nonce_digest,state_revision,recovery_epoch,expires_at,status,request_bytes,pending_bytes,created_at,decided_at,consumed_at) VALUES('ack-retire',?,?,?,?, 'human-a','infra-admin',?, ?,?,'2026-09-13T00:00:00Z','approved',X'01',X'01',?,?,?)`, []any{request.PlanID, request.PlanDigest, request.SelectionDigest, testDigest, "sha256:" + strings.Repeat("e", 64), request.StateRevision, request.RecoveryEpoch, stamp, stamp, stamp}},
		{`INSERT INTO acknowledgement_proofs(acknowledgement_id,proof_digest,status,canonical_bytes,received_at) VALUES('ack-retire',?,'approved',X'01',?)`, []any{"sha256:" + strings.Repeat("d", 64), stamp}},
		{`INSERT INTO plan_runs(run_id,plan_id,plan_digest,authorization_decision_id,acknowledgement_id,policy_version,executor_mode,executor_id,executor_binding_digest,status,cancellation_requested,rollback_status,verification_status,changed,state_revision,recovery_epoch,submit_key_digest,request_digest,canonical_bytes,created_at,updated_at) VALUES('run-retire',?,?,'decision-retire','ack-retire','1.0.0','central','central',?,'running',0,'not-requested','pending',0,?,?,?, ?,X'01',?,?)`, []any{request.PlanID, request.PlanDigest, testDigest, request.StateRevision, request.RecoveryEpoch, "sha256:" + strings.Repeat("c", 64), "sha256:" + strings.Repeat("b", 64), stamp, stamp}},
		{`INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,active_lease_id,started_at) VALUES('step-retire','run-retire',1,'op-retire','backup.local.retire','local.retention','central',?,?,?,0,'running','intent-recorded','exec-retire',?)`, []any{request.RepositoryID, request.SelectionDigest, request.ExpectedInventoryDigest, stamp}},
		{`INSERT INTO target_execution_leases(lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes) VALUES('exec-retire','run-retire','step-retire',?,?,?, ?,?,?,?,?, 'active',X'01')`, []any{request.RepositoryID, testDigest, "sha256:" + strings.Repeat("a", 64), request.RecoveryEpoch, stamp, stamp, "2026-09-12T18:30:10Z", "2026-09-12T18:30:10Z"}},
		{`INSERT INTO backup_retirement_leases(lease_id,intent_id,run_id,step_id,executor_lease_id,acknowledgement_id,human_id,retention_consumer_id,repository_class,recovery_epoch,maximum_expires_at,acquired_at) VALUES('retention-a',?,'run-retire','step-retire','exec-retire','ack-retire','human-a','retention-only',?,?,?,?)`, []any{intent.IntentID, request.RepositoryClass, request.RecoveryEpoch, "2026-09-12T18:30:01Z", stamp}},
	}
	for _, statement := range statements {
		if _, err := authority.conn.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed retention lease: %v", err)
		}
	}
	mutation := LocalRetirementMutationAttempt{MutationID: "mutation-one", LeaseID: "retention-a", Sequence: 1,
		MutationKind: "put", ObjectType: "data", ObjectName: strings.Repeat("f", 64), ObjectDigest: testDigest,
		ObjectBytes: 100, RecoveryEpoch: request.RecoveryEpoch, Attribution: request.Attribution}
	retirement := NewLocalRetirementRepository(authority)
	unlisted := mutation
	unlisted.MutationKind = "delete"
	if err := retirement.BeginLocalMutation(ctx, unlisted); err == nil {
		t.Fatal("unlisted pack deletion was journal-authorized")
	}
	overbudget := mutation
	overbudget.ObjectBytes = request.MaxRepackBytes + 1
	if err := retirement.BeginLocalMutation(ctx, overbudget); err == nil {
		t.Fatal("repack budget exceeded before any retained-object effect")
	}
	if err := retirement.BeginLocalMutation(ctx, mutation); err != nil {
		t.Fatalf("active exact lease could not journal attempt: %v", err)
	}
	if err := retirement.BeginLocalMutation(ctx, mutation); err == nil {
		t.Fatal("byte-identical attempt replay was silently reauthorized")
	}
	unresolved := mutation
	unresolved.MutationID, unresolved.Sequence = "mutation-two", 2
	if err := retirement.BeginLocalMutation(ctx, unresolved); err == nil {
		t.Fatal("unresolved mutation allowed another retained-object operation")
	}
	if err := retirement.FinishLocalMutation(ctx, LocalRetirementMutationOutcome{MutationID: mutation.MutationID, LeaseID: mutation.LeaseID,
		Status: "quarantined", QuarantineName: "data/" + mutation.ObjectName, Attribution: request.Attribution}); err == nil {
		t.Fatal("put attempt accepted a quarantine outcome")
	}
	created := LocalRetirementMutationOutcome{MutationID: mutation.MutationID, LeaseID: mutation.LeaseID, Status: "created", Attribution: request.Attribution}
	if err := retirement.FinishLocalMutation(ctx, created); err != nil {
		t.Fatalf("exact attempt outcome not durable: %v", err)
	}
	if err := retirement.FinishLocalMutation(ctx, created); err == nil {
		t.Fatal("duplicate mutation outcome silently rewritten")
	}
	unresolved.ObjectName = strings.Repeat("e", 64)
	if err := retirement.BeginLocalMutation(ctx, unresolved); err != nil {
		t.Fatalf("settled prior attempt did not admit next bounded attempt: %v", err)
	}
	if err := retirement.FinishLocalMutation(ctx, LocalRetirementMutationOutcome{MutationID: unresolved.MutationID, LeaseID: unresolved.LeaseID,
		Status: "uncertain", Attribution: request.Attribution}); err != nil {
		t.Fatalf("uncertain outcome was not durable: %v", err)
	}
	third := unresolved
	third.MutationID, third.Sequence, third.ObjectName = "mutation-three", 3, strings.Repeat("d", 64)
	if err := retirement.BeginLocalMutation(ctx, third); Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("uncertain outcome admitted another mutation: %v", err)
	}
	authority.config.Clock = func() time.Time { return time.Date(2026, 9, 12, 18, 30, 2, 0, time.UTC) }
	if err := retirement.BeginLocalMutation(ctx, third); Code(err) != generated.ErrorCodeRecoveryRequired {
		t.Fatalf("expired retention lease admitted journaled effect: %v", err)
	}
	backup := NewBackupRepository(authority)
	err = backup.AcquireBackupWriterLease(ctx, BackupWriterLeaseRequest{LeaseID: "writer-after-retire", JobID: "job-after-retire", PolicyID: "policy-a", PolicyDigest: testDigest,
		PlanID: request.PlanID, PlanDigest: request.PlanDigest, RunID: "run-after-retire", StepID: "step-after-retire", RepositoryID: request.RepositoryID,
		RepositoryClass: request.RepositoryClass, TargetID: request.RepositoryID, SourceRevision: request.SourceRevision, RecoveryEpoch: request.RecoveryEpoch,
		MaximumExpiresAt: authority.config.Clock().Add(time.Hour)})
	if Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("writer admitted during expired but unreconciled retention lease: %v", err)
	}
	if _, err := authority.conn.ExecContext(ctx, `INSERT INTO backup_jobs(job_id,policy_id,policy_digest,repository_id,repository_class,run_id,point_id,source_kind,proof_class,status,recovery_epoch,created_at,updated_at) VALUES('job-existing','policy-a',?,?,?,'run-existing','point-existing','local','fixture','pending',?,?,?)`,
		testDigest, request.RepositoryID, request.RepositoryClass, request.RecoveryEpoch, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.conn.ExecContext(ctx, `INSERT INTO recovery_points(point_id,job_id,policy_id,policy_digest,repository_id,repository_class,source_kind,proof_class,snapshot_id,snapshot_count,object_count,object_bytes,content_digest,manifest_digest,manifest_json,inventory_digest,source_revision,recovery_epoch,verification_status,created_at) VALUES('point-existing','job-existing','policy-a',?,?,?,'local','fixture',?,1,1,100,?,?,'{}',?,?,?,'pending',?)`,
		testDigest, request.RepositoryID, request.RepositoryClass, strings.Repeat("1", 64), testDigest, testDigest, testDigest, request.SourceRevision, request.RecoveryEpoch, stamp); err != nil {
		t.Fatal(err)
	}
	err = backup.AcquireBackupReadLease(ctx, BackupReadLeaseRequest{LeaseID: "reader-after-retire", PointID: "point-existing", RepositoryID: request.RepositoryID,
		RepositoryClass: request.RepositoryClass, SourceRevision: request.SourceRevision,
		Expected:         RevisionToken{StateRevision: request.StateRevision, RecoveryEpoch: request.RecoveryEpoch},
		MaximumExpiresAt: authority.config.Clock().Add(time.Hour)})
	if Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("reader admitted during expired but unreconciled retention lease: %v", err)
	}
	// Reconciliation must be explicit. Once it records a release, an ordinary
	// read may proceed again; the previous expired timestamp is insufficient.
	if _, err := authority.conn.ExecContext(ctx, `UPDATE backup_retirement_leases SET released_at=? WHERE lease_id='retention-a'`, authority.config.Clock().Add(time.Second).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if err := backup.AcquireBackupReadLease(ctx, BackupReadLeaseRequest{LeaseID: "reader-after-release", PointID: "point-existing", RepositoryID: request.RepositoryID,
		RepositoryClass: request.RepositoryClass, SourceRevision: request.SourceRevision,
		Expected:         RevisionToken{StateRevision: request.StateRevision, RecoveryEpoch: request.RecoveryEpoch},
		MaximumExpiresAt: authority.config.Clock().Add(time.Hour)}); err != nil {
		t.Fatalf("reader blocked after explicit retention release: %v", err)
	}
	if err := backup.ReleaseBackupReadLease(ctx, "reader-after-release"); err != nil {
		t.Fatal(err)
	}
	if err := backup.AcquireBackupWriterLease(ctx, BackupWriterLeaseRequest{LeaseID: "writer-after-release", JobID: "job-after-release", PolicyID: "policy-a", PolicyDigest: testDigest,
		PlanID: request.PlanID, PlanDigest: request.PlanDigest, RunID: "run-after-release", StepID: "step-after-release", RepositoryID: request.RepositoryID,
		RepositoryClass: request.RepositoryClass, TargetID: request.RepositoryID, SourceRevision: request.SourceRevision, RecoveryEpoch: request.RecoveryEpoch,
		MaximumExpiresAt: authority.config.Clock().Add(time.Hour)}); err != nil {
		t.Fatalf("writer blocked after explicit retention release and read release: %v", err)
	}
}
