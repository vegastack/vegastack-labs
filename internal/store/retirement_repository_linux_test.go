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
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func retirementStageFixture(t *testing.T, authority *Store, risk, branch string) LocalRetirementStageRequest {
	t.Helper()
	lockCatalog := LocalRetentionLockCatalog{Schema: "vegastack-labs.dev/local-retention-lock-catalog", SchemaVersion: "1.0.0",
		RepositoryID: backupidentity.StandardRepository, RepositoryClass: "standard", SourceCoverageDigest: LocalPromiseSourceCoverageDigest(),
		RecoveryEpoch: 0, Revision: 1, Complete: true, Locks: []LocalRetentionLock{}}
	_, lockDigest, err := CanonicalLocalRetentionLockCatalog(lockCatalog)
	if err != nil {
		t.Fatal(err)
	}
	request := LocalRetirementStageRequest{RepositoryID: backupidentity.StandardRepository, RepositoryClass: "standard",
		CatalogDigest: testDigest, ExpectedInventoryDigest: testDigest, LockCatalogDigest: lockDigest, SourceCoverageDigest: lockCatalog.SourceCoverageDigest, LockCatalogSequence: 1,
		Targets:        []LocalRetirementTarget{{PointID: "old-point", SnapshotID: strings.Repeat("a", 64), ManifestDigest: testDigest, InventoryDigest: testDigest, DependencyDigest: testDigest}},
		Survivors:      []LocalRetirementSurvivor{{PointID: "good-point", SnapshotID: strings.Repeat("b", 64), ManifestDigest: testDigest, InventoryDigest: testDigest, DependencyDigest: testDigest, ProofDigest: testDigest}},
		SourceRevision: 2, StateRevision: 2, RecoveryEpoch: 0, MaxWorkObjects: 10, MaxMutationBytes: 1024, MaxRepackBytes: 1024,
		CapacityTotalBytes: 10000, CapacityAvailableBytes: 5000, CapacityRetainedBytes: 1000, CapacityQuarantinedBytes: 0, CapacityExpectedGrowthBytes: 100,
		Attribution: validDeclarationStoreRequest().Attribution}
	_, digest, err := canonicalRetirementSelection(request)
	if err != nil {
		t.Fatal(err)
	}
	request.SelectionDigest = digest
	binding := credentialref.StepBinding{OperationID: "operation-a", AdapterID: "local.retention", TargetID: request.RepositoryID, ReferenceID: "reference-a", ConsumerID: "local.retention", PurposeID: "backup-retention", MaterialVersion: "version-a", ResolverID: "native-systemd", StateRevision: 2, RecoveryEpoch: 0}
	credentialDigest := credentialref.OperationManifestDigest([]credentialref.StepBinding{binding}, binding.OperationID)
	draft := validDeclarationStoreRequest()
	draft.Document.DeclarationType = "backup.retirement"
	draft.Document.Operations[0].OperationType = "backup.local.retire"
	draft.Document.Operations[0].AdapterID = "local.retention"
	draft.Document.Operations[0].TargetID = request.RepositoryID
	draft.Document.Operations[0].InputDigest = credentialDigest
	draft.Document.Operations[0].ArtifactDigest = request.ExpectedInventoryDigest
	draft.Document.Extensions = []generated.ContractExtension{{Name: "x-backup-local-retirement", ValueDigest: digest}, {Name: "x-credential-bindings", ValueDigest: credentialDigest}}
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
	commit.Plan.Operations[0].InputDigest = credentialDigest
	commit.Plan.Operations[0].ArtifactDigest = request.ExpectedInventoryDigest
	commit.Plan.Extensions = draft.Document.Extensions
	commit.DesiredDeclaration.Extensions = draft.Document.Extensions
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

func retirementLockCatalogJSON(t *testing.T) string {
	t.Helper()
	value := LocalRetentionLockCatalog{Schema: "vegastack-labs.dev/local-retention-lock-catalog", SchemaVersion: "1.0.0",
		RepositoryID: backupidentity.StandardRepository, RepositoryClass: "standard", SourceCoverageDigest: LocalPromiseSourceCoverageDigest(),
		RecoveryEpoch: 0, Revision: 1, Complete: true, Locks: []LocalRetentionLock{}}
	canonical, _, err := CanonicalLocalRetentionLockCatalog(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(canonical)
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
	status, err := NewBackupRepository(authority).ReadLocalBackupStatus(context.Background())
	if err != nil || len(status.Retirements) != 1 || status.Retirements[0].IntentID != intent.IntentID ||
		status.Retirements[0].Status != "planned" || len(status.Retirements[0].TargetPointIDs) != 1 || len(status.Retirements[0].SurvivorPointIDs) != 1 {
		t.Fatalf("sanitized retirement status=%#v err=%v", status.Retirements, err)
	}
	rawStatus, err := json.Marshal(status)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDBackupStatusData, rawStatus, generated.ContractExact) != nil {
		t.Fatalf("retirement status violates generated contract: %v", err)
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

func TestLocalRetirementSelectionBindsCapacityEvidence(t *testing.T) {
	authority := openRetirementTestStore(t)
	request := retirementStageFixture(t, authority, "destructive", "human")
	_, original, err := canonicalRetirementSelection(request)
	if err != nil {
		t.Fatal(err)
	}
	changed := request
	changed.CapacityAvailableBytes--
	_, changedDigest, err := canonicalRetirementSelection(changed)
	if err != nil || changedDigest == original {
		t.Fatalf("capacity not bound: digest=%q err=%v", changedDigest, err)
	}
	invalid := request
	invalid.CapacityTotalBytes = 0
	if _, _, err := canonicalRetirementSelection(invalid); err == nil {
		t.Fatal("missing capacity evidence admitted")
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
		{`INSERT INTO backup_retention_lock_catalog_activations(activation_id,repository_id,repository_class,catalog_digest,source_coverage_digest,canonical_json,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,acknowledgement_id,human_id,state_revision,recovery_epoch,activated_at)
			SELECT 'lock-catalog-test',?,?,?, ?,?,p.declaration_id,p.declaration_revision,p.plan_id,p.plan_digest,'run-retire','step-retire','ack-retire','human-a',?,?,? FROM immutable_plans p WHERE p.plan_id=?`, []any{request.RepositoryID, request.RepositoryClass, request.LockCatalogDigest, request.SourceCoverageDigest, retirementLockCatalogJSON(t), request.StateRevision, request.RecoveryEpoch, stamp, request.PlanID}},
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
	if err := retirement.BeginLocalMutation(ctx, mutation); err != nil {
		t.Fatalf("active exact lease could not journal attempt: %v", err)
	}
	if err := retirement.BeginLocalMutation(ctx, mutation); err == nil {
		t.Fatal("byte-identical attempt replay was silently reauthorized")
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
	unresolved := mutation
	createdDelete := mutation
	createdDelete.MutationID, createdDelete.Sequence, createdDelete.MutationKind = "mutation-two", 2, "delete"
	if err := retirement.BeginLocalMutation(ctx, createdDelete); err != nil {
		t.Fatalf("same-lease prune object could not be quarantined: %v", err)
	}
	if err := retirement.FinishLocalMutation(ctx, LocalRetirementMutationOutcome{MutationID: createdDelete.MutationID, LeaseID: createdDelete.LeaseID,
		Status: "quarantined", QuarantineName: "data/" + createdDelete.ObjectName, Attribution: request.Attribution}); err != nil {
		t.Fatalf("same-lease prune quarantine not durable: %v", err)
	}
	unresolved.MutationID, unresolved.Sequence, unresolved.ObjectName, unresolved.MutationKind = "mutation-three", 3, strings.Repeat("e", 64), "delete"
	if err := retirement.BeginLocalMutation(ctx, unresolved); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("unlisted mutation was not durably denied: %v", err)
	}
	var denied int
	if err := authority.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_retirement_mutation_attempts a JOIN backup_retirement_mutation_outcomes o ON o.mutation_id=a.mutation_id WHERE a.mutation_id=? AND o.status='denied'`, unresolved.MutationID).Scan(&denied); err != nil || denied != 1 {
		t.Fatalf("denied mutation absent from journal: count=%d err=%v", denied, err)
	}
	if _, err := retirement.LocalRetirementJournalDigest(ctx, mutation.LeaseID); Code(err) != generated.ErrorCodeRecoveryRequired {
		t.Fatalf("mixed denial remained settleable: %v", err)
	}
	third := unresolved
	third.MutationID, third.Sequence, third.ObjectName = "mutation-four", 4, strings.Repeat("d", 64)
	if err := retirement.BeginLocalMutation(ctx, third); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("denied outcome admitted another mutation: %v", err)
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

func TestClaimLocalRetirementRechecksCapacityAndAdmitsQuarantinedSharedPack(t *testing.T) {
	ctx := context.Background()
	authority := openRetirementTestStore(t)
	request := retirementStageFixture(t, authority, "destructive", "human")
	retirement := NewLocalRetirementRepository(authority)
	intent, err := retirement.StageLocalRetirement(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	stamp := authority.config.Clock().UTC().Format(time.RFC3339)
	policyBytes, _ := json.Marshal(validBackupPolicy())
	planTarget, _ := localRepositoryPlanTargetDigest(request.RepositoryID)
	var credentialDigest string
	if err := authority.conn.QueryRowContext(ctx, `SELECT json_extract(canonical_bytes,'$.operations[0].inputDigest') FROM immutable_plans WHERE plan_id=?`, request.PlanID).Scan(&credentialDigest); err != nil {
		t.Fatal(err)
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO backup_policy_drafts(draft_id,policy_id,owner_id,repository_class,revision,recovery_epoch,canonical_json,policy_digest,idempotency_key_digest,state_revision,created_by,created_at) VALUES('draft-policy','policy-a','owner-a','standard',1,0,?,?,?,1,'human-a',?)`, []any{string(policyBytes), testDigest, "sha256:" + strings.Repeat("9", 64), stamp}},
		{`INSERT INTO acknowledgement_requests(acknowledgement_id,plan_id,plan_digest,target_digest,reason_digest,human_id,authority_id,nonce_digest,state_revision,recovery_epoch,expires_at,status,request_bytes,pending_bytes,created_at,decided_at,consumed_at) VALUES('ack-claim',?,?,?,?, 'human-a','infra-admin',?, ?,?,'2026-09-13T00:00:00Z','approved',X'01',X'01',?,?,?)`, []any{request.PlanID, request.PlanDigest, planTarget, testDigest, "sha256:" + strings.Repeat("8", 64), request.StateRevision, request.RecoveryEpoch, stamp, stamp, stamp}},
		{`INSERT INTO acknowledgement_proofs(acknowledgement_id,proof_digest,status,canonical_bytes,received_at) VALUES('ack-claim',?,'approved',X'01',?)`, []any{"sha256:" + strings.Repeat("7", 64), stamp}},
		{`INSERT INTO plan_runs(run_id,plan_id,plan_digest,authorization_decision_id,acknowledgement_id,policy_version,executor_mode,executor_id,executor_binding_digest,status,cancellation_requested,rollback_status,verification_status,changed,state_revision,recovery_epoch,submit_key_digest,request_digest,canonical_bytes,created_at,updated_at) VALUES('run-claim',?,?,'decision-claim','ack-claim','1.0.0','central','central',?,'running',0,'not-requested','pending',0,?,?,?, ?,X'01',?,?)`, []any{request.PlanID, request.PlanDigest, testDigest, request.StateRevision, request.RecoveryEpoch, "sha256:" + strings.Repeat("6", 64), "sha256:" + strings.Repeat("5", 64), stamp, stamp}},
		{`INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,active_lease_id,started_at) VALUES('step-claim','run-claim',1,'operation-a','backup.local.retire','local.retention','central',?,?,?,0,'running','intent-recorded','exec-claim',?)`, []any{request.RepositoryID, credentialDigest, request.ExpectedInventoryDigest, stamp}},
		{`INSERT INTO target_execution_leases(lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes) VALUES('exec-claim','run-claim','step-claim',?,?,?, ?,?,?,?,?, 'active',X'01')`, []any{request.RepositoryID, testDigest, "sha256:" + strings.Repeat("4", 64), request.RecoveryEpoch, stamp, stamp, "2026-09-12T19:00:00Z", "2026-09-12T19:00:00Z"}},
		{`INSERT INTO backup_retention_lock_catalog_activations(activation_id,repository_id,repository_class,catalog_digest,source_coverage_digest,canonical_json,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,acknowledgement_id,human_id,state_revision,recovery_epoch,activated_at) SELECT 'lock-claim',?,?,?, ?,?,p.declaration_id,p.declaration_revision,p.plan_id,p.plan_digest,'run-claim','step-claim','ack-claim','human-a',?,?,? FROM immutable_plans p WHERE p.plan_id=?`, []any{request.RepositoryID, request.RepositoryClass, request.LockCatalogDigest, request.SourceCoverageDigest, retirementLockCatalogJSON(t), request.StateRevision, request.RecoveryEpoch, stamp, request.PlanID}},
	}
	for _, statement := range statements {
		if _, err := authority.conn.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed claim: %v", err)
		}
	}
	sharedName := strings.Repeat("c", 64)
	pointSourceRevision := request.SourceRevision + 41 // backup source revision is not the declaration revision
	for index, point := range []struct{ id, snapshot, manifest, inventory string }{{request.Targets[0].PointID, request.Targets[0].SnapshotID, request.Targets[0].ManifestDigest, request.Targets[0].InventoryDigest}, {request.Survivors[0].PointID, request.Survivors[0].SnapshotID, request.Survivors[0].ManifestDigest, request.Survivors[0].InventoryDigest}} {
		manifestJSON, _ := json.Marshal(pendingCreationManifest{PointID: point.id, DependencyInventoryDigest: request.Survivors[0].DependencyDigest})
		job := "job-claim-" + point.id
		if _, err := authority.conn.ExecContext(ctx, `INSERT INTO backup_jobs(job_id,policy_id,policy_digest,repository_id,repository_class,run_id,point_id,source_kind,proof_class,status,recovery_epoch,created_at,updated_at) VALUES(?,'policy-a',?,?,?,'run-source',?,'local','fixture','pending',0,?,?)`, job, testDigest, request.RepositoryID, request.RepositoryClass, point.id, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := authority.conn.ExecContext(ctx, `INSERT INTO recovery_points(point_id,job_id,policy_id,policy_digest,repository_id,repository_class,source_kind,proof_class,snapshot_id,snapshot_count,object_count,object_bytes,content_digest,manifest_digest,manifest_json,inventory_digest,source_revision,recovery_epoch,verification_status,created_at) VALUES(?,?,'policy-a',?,?,?,'local','fixture',?,1,1,100,?,?,?,?,?,0,'pending',?)`, point.id, job, testDigest, request.RepositoryID, request.RepositoryClass, point.snapshot, testDigest, point.manifest, string(manifestJSON), point.inventory, pointSourceRevision, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := authority.conn.ExecContext(ctx, `INSERT INTO backup_expected_objects(point_id,object_type,object_name,object_bytes,object_digest) VALUES(?,'data',?,100,?)`, point.id, sharedName, testDigest); err != nil {
			t.Fatal(err)
		}
		if index == 1 {
			if _, err := authority.conn.ExecContext(ctx, `INSERT INTO backup_read_leases(lease_id,point_id,repository_id,repository_class,source_revision,state_revision,recovery_epoch,maximum_expires_at,acquired_at,released_at) VALUES('read-claim',?,?,?,?,?,0,'2026-09-12T18:29:00Z',?,'2026-09-12T18:29:30Z')`, point.id, request.RepositoryID, request.RepositoryClass, pointSourceRevision, request.StateRevision, stamp); err != nil {
				t.Fatal(err)
			}
			// The exact proof predates the inert declaration, selection, binding,
			// and plan revisions while remaining bound to the selected survivor.
			proofRevision := request.StateRevision - 1
			wrongProof := "sha256:" + strings.Repeat("1", 64)
			if _, err := authority.conn.ExecContext(ctx, `INSERT INTO backup_local_verifications(verification_id,proof_digest,point_id,run_id,read_lease_id,status,proof_class,manifest_digest,inventory_digest,observed_digest,content_digest,catalog_digest,dependency_digest,key_reference_id,source_revision,state_revision,recovery_epoch,full_read_at,functional_restored_at,reason_code,created_at) VALUES('verify-claim-wrong',?,?,'run-source','read-claim','local-verified','live',?,?,?,?,?,?,'key-a',?,?,0,?,?, '',?)`, wrongProof, point.id, point.manifest, point.inventory, point.inventory, testDigest, testDigest, request.Survivors[0].DependencyDigest, pointSourceRevision, proofRevision, stamp, stamp, stamp); err != nil {
				t.Fatal(err)
			}
			if _, err := authority.conn.ExecContext(ctx, `INSERT INTO backup_repository_capacity_observations(observation_id,verification_id,repository_id,repository_class,total_bytes,available_bytes,quarantined_bytes,recovery_epoch,observed_at) VALUES('capacity-claim','verify-claim-wrong',?,?,?, ?,?,0,?)`, request.RepositoryID, request.RepositoryClass, request.CapacityTotalBytes, request.CapacityAvailableBytes, request.CapacityQuarantinedBytes, stamp); err != nil {
				t.Fatal(err)
			}
			wrongClaim := LocalRetirementClaimRequest{IntentID: intent.IntentID, LeaseID: "retention-claim-wrong", PlanID: request.PlanID, PlanDigest: request.PlanDigest, RunID: "run-claim", StepID: "step-claim", ExecutorLeaseID: "exec-claim", RetentionConsumerID: "backup-retention", RecoveryEpoch: 0, MaximumExpiresAt: time.Date(2026, 9, 12, 19, 0, 0, 0, time.UTC), Attribution: request.Attribution}
			if _, err := retirement.ClaimLocalRetirement(ctx, wrongClaim); Code(err) != generated.ErrorCodePlanStale || !strings.Contains(err.Error(), "local-retirement-survivor-proof") {
				t.Fatalf("mismatched survivor proof admitted: %v", err)
			}
			if _, err := authority.conn.ExecContext(ctx, `INSERT INTO backup_local_verifications(verification_id,proof_digest,point_id,run_id,read_lease_id,status,proof_class,manifest_digest,inventory_digest,observed_digest,content_digest,catalog_digest,dependency_digest,key_reference_id,source_revision,state_revision,recovery_epoch,full_read_at,functional_restored_at,reason_code,created_at) VALUES('verify-claim',?,?,'run-source','read-claim','local-verified','live',?,?,?,?,?,?,'key-a',?,?,0,?,?, '',?)`, request.Survivors[0].ProofDigest, point.id, point.manifest, point.inventory, point.inventory, testDigest, testDigest, request.Survivors[0].DependencyDigest, pointSourceRevision, proofRevision, stamp, stamp, stamp); err != nil {
				t.Fatal(err)
			}
			if _, err := authority.conn.ExecContext(ctx, `INSERT INTO backup_local_last_good(repository_class,point_id,verification_id,state_revision,recovery_epoch,advanced_at) VALUES(?,?,'verify-claim',?,0,?)`, request.RepositoryClass, point.id, request.StateRevision, stamp); err != nil {
				t.Fatal(err)
			}
		}
	}
	claimRequest := LocalRetirementClaimRequest{IntentID: intent.IntentID, LeaseID: "retention-claim", PlanID: request.PlanID, PlanDigest: request.PlanDigest, RunID: "run-claim", StepID: "step-claim", ExecutorLeaseID: "exec-claim", RetentionConsumerID: "backup-retention", RecoveryEpoch: 0, MaximumExpiresAt: time.Date(2026, 9, 12, 19, 0, 0, 0, time.UTC), Attribution: request.Attribution}
	lease, err := retirement.ClaimLocalRetirement(ctx, claimRequest)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	nonceDigest := "sha256:" + strings.Repeat("3", 64)
	if err := retirement.BeginRetirementCustody(ctx, lease.LeaseID, nonceDigest); err != nil {
		t.Fatal(err)
	}
	replacementName := strings.Repeat("d", 64)
	replacement := LocalRetirementMutationAttempt{MutationID: "mutation-replacement-pack", LeaseID: lease.LeaseID, MutationKind: "put", ObjectType: "data", ObjectName: replacementName, ObjectDigest: testDigest, Sequence: 1, ObjectBytes: 50, RecoveryEpoch: 0, Attribution: request.Attribution}
	if err := retirement.BeginLocalMutation(ctx, replacement); err != nil {
		t.Fatalf("successor replacement was not admitted: %v", err)
	}
	if err := retirement.FinishLocalMutation(ctx, LocalRetirementMutationOutcome{MutationID: replacement.MutationID, LeaseID: lease.LeaseID, Status: "created", Attribution: request.Attribution}); err != nil {
		t.Fatal(err)
	}
	mutation := LocalRetirementMutationAttempt{MutationID: "mutation-shared-pack", LeaseID: lease.LeaseID, MutationKind: "delete", ObjectType: "data", ObjectName: sharedName, ObjectDigest: testDigest, Sequence: 2, ObjectBytes: 100, RecoveryEpoch: 0, Attribution: request.Attribution}
	if err := retirement.BeginLocalMutation(ctx, mutation); err != nil {
		t.Fatalf("shared survivor pack was not admitted to reversible quarantine: %v", err)
	}
	if err := retirement.FinishLocalMutation(ctx, LocalRetirementMutationOutcome{MutationID: mutation.MutationID, LeaseID: lease.LeaseID, Status: "quarantined", QuarantineName: "data/" + sharedName, Attribution: request.Attribution}); err != nil {
		t.Fatal(err)
	}
	if err := retirement.FinishRetirementCustody(ctx, nonceDigest, "succeeded"); err != nil {
		t.Fatal(err)
	}
	authority.config.Clock = func() time.Time { return time.Date(2026, 9, 12, 18, 30, 1, 0, time.UTC) }
	journalDigest, err := retirement.LocalRetirementJournalDigest(ctx, lease.LeaseID)
	if err != nil {
		t.Fatal(err)
	}
	successorObjects := []ExpectedObjectRow{{Type: "data", Name: replacementName, Bytes: 50, Digest: testDigest}}
	successorDigest := pendingInventoryDigest(successorObjects)
	generationDigest, err := retirement.CommitLocalRetirementSuccess(ctx, LocalRetirementSettlement{
		IntentID: intent.IntentID, LeaseID: lease.LeaseID, SuccessorInventoryDigest: successorDigest,
		JournalDigest: journalDigest, SurvivorProofDigest: testDigest, SurvivorPointIDs: []string{request.Survivors[0].PointID},
		SuccessorObjects: successorObjects, MeasuredReclaimBytes: 150, RecoveryEpoch: 0,
	})
	if err != nil {
		t.Fatalf("settle successor generation: %v", err)
	}
	successor, err := NewBackupRepository(authority).GetLocalRetirementSuccessorForPoint(ctx, request.Survivors[0].PointID)
	if err != nil || successor.GenerationDigest != generationDigest || successor.PredecessorInventoryDigest != request.ExpectedInventoryDigest || successor.SuccessorInventoryDigest != successorDigest || len(successor.Survivors) != 1 || successor.Survivors[0] != request.Survivors[0] || len(successor.Objects) != 1 || successor.Objects[0] != successorObjects[0] {
		t.Fatalf("successor not consumable by original survivor binding: successor=%#v err=%v", successor, err)
	}
	var currentSuccessor *localRetirementCurrentSuccessor
	if err := authority.Read(ctx, func(tx ReadTx) error {
		var loadErr error
		currentSuccessor, loadErr = loadLocalRetirementCurrentSuccessor(ctx, tx, request.RepositoryClass, 0)
		return loadErr
	}); err != nil {
		t.Fatal(err)
	}
	if currentSuccessor == nil || currentSuccessor.Digest != generationDigest || !currentSuccessor.RetiredPointIDs[request.Targets[0].PointID] || currentSuccessor.RetiredPointIDs[request.Survivors[0].PointID] {
		t.Fatalf("successor retirement history=%#v", currentSuccessor)
	}
	if isPostSuccessorRecoveryPoint(currentSuccessor, request.Targets[0].PointID, "", currentSuccessor.StateRevision+1, currentSuccessor.RecordedAt.Add(time.Second)) {
		t.Fatal("later verification resurrected an immutable retired target")
	}
	if !isPostSuccessorRecoveryPoint(currentSuccessor, "point-after-successor", "", currentSuccessor.StateRevision, currentSuccessor.RecordedAt.Add(time.Second)) {
		t.Fatal("new verified point after successor was excluded")
	}
	if isPostSuccessorRecoveryPoint(currentSuccessor, "point-after-successor", generationDigest, currentSuccessor.StateRevision+1, currentSuccessor.RecordedAt.Add(time.Second)) || isPostSuccessorRecoveryPoint(currentSuccessor, "point-after-successor", "", currentSuccessor.StateRevision, currentSuccessor.RecordedAt) {
		t.Fatal("stale or generation-bound point was admitted as a new recovery point")
	}

}
