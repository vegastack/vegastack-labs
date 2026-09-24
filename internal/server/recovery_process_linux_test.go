//go:build linux

package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/store"
)

const recoveryLockHelperEnvironment = "VSK_RECOVERY_LOCK_HELPER"
const recoveryAuthorityHelperEnvironment = "VSK_RECOVERY_AUTHORITY_HELPER"

// TestRecoveryPromotionLockIsExclusiveAcrossProcesses exercises the real
// no-follow flock used at startup. A second replacement process cannot enter
// promotion while the first owns the authority lock, and the lock becomes
// available only after the owner closes it.
func TestRecoveryPromotionLockIsExclusiveAcrossProcesses(t *testing.T) {
	if os.Getenv(recoveryLockHelperEnvironment) == "1" {
		runRecoveryLockHelper(t)
		return
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "control.db")
	paths, err := recovery.DeriveCandidatePaths(databasePath, "plan-process-a")
	if err != nil {
		t.Fatal(err)
	}
	storage := recovery.LocalCandidateStorage{ExpectedUID: uint32(os.Geteuid())}
	lock, err := storage.AcquireAuthorityLock(context.Background(), paths)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestRecoveryPromotionLockIsExclusiveAcrossProcesses$")
	command.Env = append(os.Environ(), recoveryLockHelperEnvironment+"=1", "VSK_RECOVERY_DATABASE="+databasePath, "VSK_RECOVERY_EXPECT_BLOCKED=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("blocked helper: %v: %s", err, output)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	command = exec.Command(os.Args[0], "-test.run=^TestRecoveryPromotionLockIsExclusiveAcrossProcesses$")
	command.Env = append(os.Environ(), recoveryLockHelperEnvironment+"=1", "VSK_RECOVERY_DATABASE="+databasePath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("released helper: %v: %s", err, output)
	}
}

// TestReturningFormerControllerCannotMutatePromotedAuthority first boots the
// replacement controller against the promoted database, then lets it exit and
// starts a distinct returning-former process with its preserved epoch token.
// The separate lock test above owns simultaneous-writer exclusion; this test
// deliberately releases that lock so it can reach the epoch admission check.
func TestReturningFormerControllerCannotMutatePromotedAuthority(t *testing.T) {
	if mode := os.Getenv(recoveryAuthorityHelperEnvironment); mode != "" {
		runRecoveryAuthorityHelper(t, mode)
		return
	}
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "control.db")
	config := func(path string, mode store.OpenMode) store.Config {
		return store.Config{DatabasePath: path, Mode: mode, BusyTimeout: 250 * time.Millisecond, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "recovery-process-test", BuildVersion: "recovery-process-test"}
	}
	authority, err := store.Open(ctx, config(databasePath, store.InitializeNew))
	if err != nil {
		t.Fatal(err)
	}
	prior, err := authority.CurrentAuthority(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	artifacts := processOldAuthorityArtifacts(t)
	seedProcessOldAuthorityArtifacts(t, databasePath, artifacts)
	binding := processRecoveryBinding(prior.InstanceID, prior.RecoveryEpoch)
	opener := func(ctx context.Context, path string) (*store.Store, error) {
		return store.Open(ctx, config(path, store.OpenExisting))
	}
	if err := (recovery.StoreCandidateAuthority{Open: opener}).PrepareRecoveredAuthority(ctx, databasePath, binding, recovery.AuditContinuity{IndependentCheckpointDigest: processRecoveryDigest("9"), DecisionDigest: binding.AuditDecisionDigest}); err != nil {
		t.Fatal(err)
	}
	holder := exec.Command(os.Args[0], "-test.run=^TestReturningFormerControllerCannotMutatePromotedAuthority$")
	holder.Env = append(os.Environ(), recoveryAuthorityHelperEnvironment+"=replacement", "VSK_RECOVERY_DATABASE="+databasePath)
	if output, err := holder.CombinedOutput(); err != nil || strings.TrimSpace(string(output)) != "replacement-ready" {
		t.Fatalf("replacement start = %q, %v", output, err)
	}
	former := exec.Command(os.Args[0], "-test.run=^TestReturningFormerControllerCannotMutatePromotedAuthority$")
	former.Env = append(os.Environ(), recoveryAuthorityHelperEnvironment+"=former", "VSK_RECOVERY_DATABASE="+databasePath, "VSK_RECOVERY_PRIOR_EPOCH=0")
	if output, err := former.CombinedOutput(); err != nil {
		t.Fatalf("returning former mutated or failed ambiguously: %v: %s", err, output)
	}
}

func runRecoveryAuthorityHelper(t *testing.T, mode string) {
	path := os.Getenv("VSK_RECOVERY_DATABASE")
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: path, Mode: store.OpenExisting, BusyTimeout: 250 * time.Millisecond, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "recovery-process-test", BuildVersion: "recovery-process-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	switch mode {
	case "replacement":
		if health, err := authority.Health(context.Background()); err != nil || !health.RecoveryPending || health.MutationEnabled || health.Revision.RecoveryEpoch != 1 {
			t.Fatalf("replacement health = %#v, %v", health, err)
		}
		_, _ = os.Stdout.WriteString("replacement-ready\n")
	case "former":
		health, err := authority.Health(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !health.RecoveryPending || health.MutationEnabled || health.Revision.RecoveryEpoch != 1 {
			t.Fatalf("former observed non-pending replacement health = %#v", health)
		}
		artifacts := processOldAuthorityArtifacts(t)
		assertProcessOldAuthorityDenied(t, authority, artifacts)
		prior := store.RevisionToken{StateRevision: health.Revision.StateRevision, RecoveryEpoch: 0}
		if _, err := authority.WriteIntent(context.Background(), &prior, func(store.IntentTx) error { return nil }); store.Code(err) != generated.ErrorCodeRecoveryEpochMismatch {
			t.Fatalf("former write code = %s", store.Code(err))
		}
	default:
		t.Fatal("unknown helper mode")
	}
}

type processAuthorityArtifacts struct {
	Plan               generated.Plan
	Run                generated.Run
	Acknowledgement    generated.Acknowledgement
	AckRequest         generated.AcknowledgementRequest
	BrowserRaw         string
	BrowserDigest      string
	BrowserBinding     string
	Lease              generated.ExecutorLease
	Renewal            store.ExecutorLeaseRenewalRequest
	LifecycleBinding   credentialref.LifecycleBinding
	CredentialStage    store.CredentialStageRequest
	ReceiptPersistence store.ExecutorReceiptPersistenceRequest
}

func processOldAuthorityArtifacts(t *testing.T) processAuthorityArtifacts {
	t.Helper()
	created := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	readable := "old authority process plan\n"
	readableSum := sha256.Sum256([]byte(readable))
	human := "human-process"
	ackID := "ack-old-process"
	fingerprint := processRecoveryDigest("6")
	plan := generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", DeclarationID: "declaration-old-process", Binding: generated.PlanBinding{RecoveryEpoch: 0, PriorStateRevision: 0, StateRevision: 1, DeclarationRevision: 1, ObservationFingerprint: processRecoveryDigest("7"), TargetDigest: processRecoveryDigest("8"), ReasonDigest: processRecoveryDigest("9"), PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0"}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: "operation-old-process", OperationType: string(credentialref.ActionStage), AdapterID: "core.credential", ExecutorID: "executor-central", TargetID: "target-old-process", InputDigest: fingerprint, ArtifactDigest: fingerprint, Idempotent: true}}, Status: "planned", Risk: "routine", AuthorizationBranch: "human", ExecutorMode: "central", CreatedAt: created.Format(time.RFC3339), ExpiresAt: created.Add(30 * time.Minute).Format(time.RFC3339), ReadableDigest: "sha256:" + hex.EncodeToString(readableSum[:]), Extensions: []generated.ContractExtension{}}
	preimage, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	planSum := sha256.Sum256(preimage)
	plan.PlanDigest = "sha256:" + hex.EncodeToString(planSum[:])
	plan.PlanID = "plan-" + hex.EncodeToString(planSum[:16])
	ackRequest := generated.AcknowledgementRequest{Schema: generated.SchemaIDAcknowledgementRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, HumanID: human, AuthorityID: "authority-process", NonceDigest: processRecoveryDigest("a"), StateRevision: 1, RecoveryEpoch: 0, ExpiresAt: plan.ExpiresAt, Extensions: []generated.ContractExtension{}}
	ack := generated.Acknowledgement{Schema: generated.SchemaIDAcknowledgement, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, HumanID: human, AuthorityID: ackRequest.AuthorityID, NonceDigest: ackRequest.NonceDigest, StateRevision: 1, RecoveryEpoch: 0, ExpiresAt: plan.ExpiresAt, AcknowledgementID: ackID, ProofDigest: processRecoveryDigest("b"), Status: "approved", ReceivedAt: created.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	run := generated.Run{Schema: generated.SchemaIDRun, SchemaVersion: "1.0.0", RunID: "run-old-process", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, AuthorizationDecisionID: "decision-old-process", AcknowledgementID: &ackID, PolicyVersion: "1.0.0", ExecutorMode: "central", ExecutorID: "executor-central", ExecutorBindingDigest: processRecoveryDigest("c"), Status: "running", Steps: []generated.RunStep{{Sequence: 1, OperationID: plan.Operations[0].OperationID, OperationType: plan.Operations[0].OperationType, AdapterID: plan.Operations[0].AdapterID, ExecutorID: plan.Operations[0].ExecutorID, TargetID: plan.Operations[0].TargetID, InputDigest: fingerprint, ArtifactDigest: fingerprint, Idempotent: true, StepID: "step-old-process", Status: "running", EffectState: "intent-recorded"}}, CancellationRequested: false, RollbackStatus: "not-requested", VerificationStatus: "pending", Changed: false, StateRevision: 1, RecoveryEpoch: 0, CreatedAt: created.Format(time.RFC3339), UpdatedAt: created.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	lease := generated.ExecutorLease{Schema: generated.SchemaIDExecutorLease, SchemaVersion: "1.0.0", LeaseID: "lease-old-process", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RunID: run.RunID, StepID: run.Steps[0].StepID, OperationID: run.Steps[0].OperationID, ExecutorID: run.ExecutorID, AdapterID: run.Steps[0].AdapterID, TargetID: run.Steps[0].TargetID, ArtifactDigest: fingerprint, BindingDigest: run.ExecutorBindingDigest, NonceDigest: processRecoveryDigest("d"), RecoveryEpoch: 0, ClaimedAt: created.Format(time.RFC3339), RenewAfter: created.Add(20 * time.Second).Format(time.RFC3339), LeaseExpiresAt: created.Add(60 * time.Second).Format(time.RFC3339), MaximumExpiresAt: created.Add(60 * time.Second).Format(time.RFC3339), Status: "active", Extensions: []generated.ContractExtension{}}
	renewal := store.ExecutorLeaseRenewalRequest{Request: generated.ExecutorRenewRequest{Schema: generated.SchemaIDExecutorRenewRequest, SchemaVersion: "1.0.0", LeaseID: lease.LeaseID, BindingDigest: lease.BindingDigest, NonceDigest: lease.NonceDigest, RecoveryEpoch: 0, Extensions: []generated.ContractExtension{}}, NextNonceDigest: processRecoveryDigest("e"), At: created.Add(20 * time.Second), Attribution: processAttribution(human)}
	draft, consumer, purpose := "draft-old-process", "consumer-old-process", "purpose-old-process"
	draftRevision := int64(1)
	lifecycle := credentialref.LifecycleBinding{OperationID: run.Steps[0].OperationID, Action: credentialref.ActionStage, DraftID: &draft, ImportDraftStateRevision: &draftRevision, ImportDraftConsumerID: &consumer, ImportDraftPurposeID: &purpose, ReferenceID: "reference-old-process", ConsumerIDs: []string{consumer}, RequiredDeniedConsumerIDs: []string{}, MaterialVersion: "version-old-process", ResolverID: "native-systemd", TargetID: run.Steps[0].TargetID, CiphertextFingerprint: fingerprint, StateRevision: 1, RecoveryEpoch: 0}
	stage := store.CredentialStageRequest{Reference: generated.CredentialReference{Schema: generated.SchemaIDCredentialReference, SchemaVersion: "1.1.0", ReferenceID: lifecycle.ReferenceID, ConsumerID: consumer, PurposeID: purpose, TargetID: lifecycle.TargetID, ResolverID: lifecycle.ResolverID, MaterialVersion: lifecycle.MaterialVersion, Fingerprint: fingerprint, Status: "staged", StateRevision: 2, RecoveryEpoch: 0, VerifiedConsumerIDs: []string{}}, DeclarationID: plan.DeclarationID, DeclarationRevision: 1, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RunID: run.RunID, StepID: run.Steps[0].StepID, LeaseID: lease.LeaseID, HumanID: human, Expected: store.RevisionToken{StateRevision: 1, RecoveryEpoch: 0}, Attribution: processAttribution(human), KeyDigest: processRecoveryDigest("f"), RequestDigest: processRecoveryDigest("1")}
	receipt := generated.ExecutionReceipt{Schema: generated.SchemaIDExecutionReceipt, SchemaVersion: "1.0.0", LeaseID: lease.LeaseID, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RunID: run.RunID, StepID: run.Steps[0].StepID, OperationID: run.Steps[0].OperationID, ExecutorID: run.ExecutorID, AdapterID: run.Steps[0].AdapterID, TargetID: run.Steps[0].TargetID, ArtifactDigest: fingerprint, BindingDigest: lease.BindingDigest, NonceDigest: lease.NonceDigest, RecoveryEpoch: 0, ReceiptID: "receipt-old-process", Status: "succeeded", ResultDigest: processRecoveryDigest("2"), RecordedAt: created.Add(time.Second).Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	request := generated.ExecutionReceiptRequest{Schema: generated.SchemaIDExecutionReceiptRequest, SchemaVersion: "1.0.0", Receipt: receipt, ExpectedBindingDigest: lease.BindingDigest, Extensions: []generated.ContractExtension{}}
	raw := strings.Repeat("A", 43)
	browserDigest, err := store.BrowserSessionDigest(raw)
	if err != nil {
		t.Fatal(err)
	}
	return processAuthorityArtifacts{Plan: plan, Run: run, Acknowledgement: ack, AckRequest: ackRequest, BrowserRaw: raw, BrowserDigest: browserDigest, BrowserBinding: processRecoveryDigest("3"), Lease: lease, Renewal: renewal, LifecycleBinding: lifecycle, CredentialStage: stage, ReceiptPersistence: store.ExecutorReceiptPersistenceRequest{Request: request, At: created.Add(time.Second), Attribution: processAttribution(human)}}
}

func processAttribution(human string) audit.Attribution {
	return audit.Attribution{AuthenticatedPrincipalID: human, AuthenticatedPrincipalMethod: "local-os-peer", ResponsibleHumanPrincipalID: &human}
}

func seedProcessOldAuthorityArtifacts(t *testing.T, databasePath string, artifacts processAuthorityArtifacts) {
	t.Helper()
	database, err := sql.Open("sqlite3", (&url.URL{Scheme: "file", Path: databasePath, RawQuery: "mode=rw&_txlock=immediate"}).String())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	planBytes := processJSON(t, artifacts.Plan)
	declaration := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: artifacts.Plan.DeclarationID, DeclarationType: "credential", Revision: 1, StateRevision: 1, RecoveryEpoch: 0, ContentDigest: processRecoveryDigest("4"), Status: "committed", Operations: []generated.DeclarationOperation{}, CreatedAt: artifacts.Plan.CreatedAt, CreatedBy: "human-process", AgentSessionID: "session-old-process", Extensions: []generated.ContractExtension{}}
	declarationBytes := processJSON(t, declaration)
	requestBytes := processJSON(t, artifacts.AckRequest)
	pending := artifacts.Acknowledgement
	pending.Status = "pending"
	pending.ProofDigest = processRecoveryDigest("5")
	pendingBytes := processJSON(t, pending)
	proofBytes := processJSON(t, artifacts.Acknowledgement)
	runBytes := processJSON(t, artifacts.Run)
	leaseBytes := processJSON(t, artifacts.Lease)
	bindingBytes := processJSON(t, artifacts.LifecycleBinding)
	created := artifacts.Run.CreatedAt
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO declaration_revisions(declaration_id,declaration_revision,declaration_type,state_revision,recovery_epoch,content_digest,reason_digest,status,canonical_bytes,created_at,created_by,agent_session_id) VALUES(?,1,'credential',1,0,?,?,'committed',?,?,?,?,?)`, []any{artifacts.Plan.DeclarationID, declaration.ContentDigest, artifacts.Plan.Binding.ReasonDigest, declarationBytes, created, declaration.CreatedBy, declaration.AgentSessionID}},
		{`INSERT INTO immutable_plans(plan_id,plan_digest,declaration_id,declaration_revision,state_revision,recovery_epoch,observation_fingerprint,idempotency_key_digest,request_digest,canonical_bytes,readable_plan,readable_digest,created_at,expires_at) VALUES(?,?,?,1,1,0,?,?,?,?,?,?,?,?)`, []any{artifacts.Plan.PlanID, artifacts.Plan.PlanDigest, artifacts.Plan.DeclarationID, artifacts.Plan.Binding.ObservationFingerprint, processRecoveryDigest("6"), processRecoveryDigest("7"), planBytes, "old authority process plan\n", artifacts.Plan.ReadableDigest, artifacts.Plan.CreatedAt, artifacts.Plan.ExpiresAt}},
		{`INSERT INTO acknowledgement_requests(acknowledgement_id,plan_id,plan_digest,target_digest,reason_digest,human_id,authority_id,nonce_digest,state_revision,recovery_epoch,expires_at,status,request_bytes,pending_bytes,created_at,decided_at,consumed_at) VALUES(?,?,?,?,?,?,?,?,1,0,?,'approved',?,?,?,?,NULL)`, []any{artifacts.Acknowledgement.AcknowledgementID, artifacts.Plan.PlanID, artifacts.Plan.PlanDigest, artifacts.Plan.Binding.TargetDigest, artifacts.Plan.Binding.ReasonDigest, artifacts.Acknowledgement.HumanID, artifacts.Acknowledgement.AuthorityID, artifacts.Acknowledgement.NonceDigest, artifacts.Plan.ExpiresAt, requestBytes, pendingBytes, created, created}},
		{`INSERT INTO acknowledgement_proofs(acknowledgement_id,proof_digest,status,canonical_bytes,received_at) VALUES(?,?,'approved',?,?)`, []any{artifacts.Acknowledgement.AcknowledgementID, artifacts.Acknowledgement.ProofDigest, proofBytes, artifacts.Acknowledgement.ReceivedAt}},
		{`INSERT INTO plan_runs(run_id,plan_id,plan_digest,authorization_decision_id,acknowledgement_id,policy_version,executor_mode,executor_id,executor_binding_digest,status,cancellation_requested,rollback_status,verification_status,verification_digest,changed,state_revision,recovery_epoch,submit_key_digest,request_digest,canonical_bytes,created_at,updated_at) VALUES(?,?,?,?,?,'1.0.0','central','executor-central',?,'running',0,'not-requested','pending',NULL,0,1,0,?,?,?,?,?)`, []any{artifacts.Run.RunID, artifacts.Run.PlanID, artifacts.Run.PlanDigest, artifacts.Run.AuthorizationDecisionID, artifacts.Acknowledgement.AcknowledgementID, artifacts.Run.ExecutorBindingDigest, processRecoveryDigest("8"), processRecoveryDigest("9"), runBytes, created, created}},
		{`INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,active_lease_id,started_at) VALUES(?,?,1,?,?,?,?,?,?,?,1,'running','intent-recorded',?,?)`, []any{artifacts.Run.Steps[0].StepID, artifacts.Run.RunID, artifacts.Run.Steps[0].OperationID, artifacts.Run.Steps[0].OperationType, artifacts.Run.Steps[0].AdapterID, artifacts.Run.Steps[0].ExecutorID, artifacts.Run.Steps[0].TargetID, artifacts.Run.Steps[0].InputDigest, artifacts.Run.Steps[0].ArtifactDigest, artifacts.Lease.LeaseID, created}},
		{`INSERT INTO target_execution_leases(lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes,lease_kind,last_renewed_at,renewal_count) VALUES(?,?,?,?,?,?,0,?,?,?,?, 'active',?,'central',NULL,0)`, []any{artifacts.Lease.LeaseID, artifacts.Lease.RunID, artifacts.Lease.StepID, artifacts.Lease.TargetID, artifacts.Lease.BindingDigest, artifacts.Lease.NonceDigest, artifacts.Lease.ClaimedAt, artifacts.Lease.RenewAfter, artifacts.Lease.LeaseExpiresAt, artifacts.Lease.MaximumExpiresAt, leaseBytes}},
		{`INSERT INTO credential_lifecycle_bindings(binding_id,declaration_id,declaration_revision,operation_id,action,reference_id,binding_digest,binding_bytes,recovery_epoch,created_at) VALUES('binding-old-process',?,1,?,?,?,?,?,0,?)`, []any{artifacts.Plan.DeclarationID, artifacts.LifecycleBinding.OperationID, string(artifacts.LifecycleBinding.Action), artifacts.LifecycleBinding.ReferenceID, credentialref.LifecycleManifestDigestOf(artifacts.LifecycleBinding), bindingBytes, created}},
		{`INSERT INTO read_principals(principal_id,status,grant_revision,created_at,updated_at) VALUES('principal-old-process','active',1,?,?)`, []any{created, created}},
		{`INSERT INTO remote_identity_bindings(binding_digest,principal_id,status,created_at,updated_at) VALUES(?,'principal-old-process','active',?,?)`, []any{artifacts.BrowserBinding, created, created}},
		{`INSERT INTO browser_sessions(session_digest,binding_digest,principal_id,status,recovery_epoch,grant_revision,issued_at,last_seen_at,idle_expires_at,absolute_expires_at,external_expires_at) VALUES(?,?,'principal-old-process','active',0,1,?,?,?,?,?)`, []any{artifacts.BrowserDigest, artifacts.BrowserBinding, created, created, "2099-01-01T00:15:00Z", "2099-01-01T08:00:00Z", "2099-01-01T08:00:00Z"}},
	}
	tx, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, statement := range statements {
		if _, err := tx.Exec(statement.query, statement.args...); err != nil {
			t.Fatalf("seed old authority artifact: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func assertProcessOldAuthorityDenied(t *testing.T, authority *store.Store, artifacts processAuthorityArtifacts) {
	t.Helper()
	ctx := context.Background()
	attemptRun := artifacts.Run
	attemptRun.RunID = "run-old-process-attempt"
	attemptRun.Status = "queued"
	attemptRun.AcknowledgementID = nil
	attemptRun.Steps[0].StepID = "step-old-process-attempt"
	attemptRun.Steps[0].Status = "queued"
	attemptRun.Steps[0].EffectState = "not-started"
	assertProcessDenial(t, "plan", generated.ErrorCodeRecoveryEpochMismatch, func() error {
		_, err := store.NewRunRepository(authority).Create(ctx, store.RunCreateRequest{Run: attemptRun, SubmitKeyDigest: audit.Fingerprint(processRecoveryDigest("a")), RequestDigest: audit.Fingerprint(processRecoveryDigest("b")), Attribution: processAttribution("human-process")})
		return err
	})
	assertProcessDenial(t, "acknowledgement", generated.ErrorCodeRecoveryEpochMismatch, func() error {
		_, _, err := store.NewAcknowledgementRepository(authority).Consume(ctx, artifacts.Plan.PlanID, time.Date(2099, 1, 1, 0, 1, 0, 0, time.UTC))
		return err
	})
	assertProcessDenial(t, "browser session", generated.ErrorCodePrerequisiteBlocked, func() error {
		_, err := authority.ValidateAndTouchBrowserSession(ctx, artifacts.BrowserRaw, artifacts.BrowserBinding, time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC))
		return err
	})
	assertProcessDenial(t, "executor lease", generated.ErrorCodePrerequisiteBlocked, func() error {
		_, err := store.NewExecutorLeaseRepository(authority).Renew(ctx, artifacts.Renewal)
		return err
	})
	assertProcessDenial(t, "credential", generated.ErrorCodeRecoveryEpochMismatch, func() error {
		_, err := store.NewCredentialRepository(authority).ApplyCredentialLifecycle(ctx, store.CredentialLifecycleApplyRequest{Binding: artifacts.LifecycleBinding, Stage: artifacts.CredentialStage})
		return err
	})
	assertProcessDenial(t, "receipt", generated.ErrorCodePrerequisiteBlocked, func() error {
		_, err := store.NewExecutorLeaseRepository(authority).RecordReceipt(ctx, artifacts.ReceiptPersistence)
		return err
	})
}

func assertProcessDenial(t *testing.T, name, want string, attempt func() error) {
	t.Helper()
	if got := store.Code(attempt()); got != want {
		t.Fatalf("former %s code = %q, want %q", name, got, want)
	}
}

func processJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func processRecoveryBinding(priorInstance string, priorEpoch int64) generated.RestoreBinding {
	source := generated.RestoreSourceBinding{Schema: generated.SchemaIDRestoreSourceBinding, SchemaVersion: "1.1.0", PointID: "point-process", PointDigest: processRecoveryDigest("1"), ManifestDigest: processRecoveryDigest("2"), VerificationDigest: processRecoveryDigest("3"), SourceClass: "local", RepositoryGenerationID: "generation-process", KeyReferenceID: "key-process", DeclaredRPOSeconds: 3600, CreatedAt: "2026-09-24T05:00:00Z", VerifiedAt: "2026-09-24T05:30:00Z", RecoveryEpoch: priorEpoch, DependencyDigests: []string{processRecoveryDigest("4")}, RequiredDependencies: []generated.RestoreDependencyBinding{{DependencyID: "restic-binary", Kind: "binary", Digest: processRecoveryDigest("4")}}, TargetReleaseBuildID: "build-process", TargetToolVersion: "1.0.0", TargetSchemaVersion: "24"}
	return generated.RestoreBinding{Schema: generated.SchemaIDRestoreBinding, SchemaVersion: "1.1.0", Source: source, PointID: source.PointID, DependencyIDs: []string{"dependency-process"}, TargetIDs: []string{"control-process"}, TargetDigest: processRecoveryDigest("5"), PlanID: "plan-process", PlanDigest: processRecoveryDigest("a"), HumanAcknowledgementID: "ack-process", FenceSetDigest: processRecoveryDigest("b"), AuditDecisionDigest: processRecoveryDigest("c"), CandidateDigest: processRecoveryDigest("d"), FormerHostID: "former-host", ReplacementHostID: "replacement-host", RecoveryDraftID: "draft-process", CiphertextFingerprint: processRecoveryDigest("e"), SourceAdmissionDigest: processRecoveryDigest("f"), FenceQualificationDigest: processRecoveryDigest("1"), RecoveryRunID: "run-process", RecoveryStepID: "step-process", RecoveryLeaseID: "lease-process", RecoveryChallengeID: "challenge-process", RecoveryReceiptID: "receipt-process", CanaryRunID: "canary-run-process", CanaryStepID: "canary-step-process", CanaryLeaseID: "canary-lease-process", CanaryChallengeID: "canary-challenge-process", CanaryReceiptID: "canary-receipt-process", CanaryBindingDigest: processRecoveryDigest("2"), PriorInstanceID: priorInstance, NewInstanceID: "instance-replacement-process", PriorRecoveryEpoch: priorEpoch, NextRecoveryEpoch: priorEpoch + 1, Status: "planned"}
}

func processRecoveryDigest(letter string) string { return "sha256:" + strings.Repeat(letter, 64) }

func runRecoveryLockHelper(t *testing.T) {
	paths, err := recovery.DeriveCandidatePaths(os.Getenv("VSK_RECOVERY_DATABASE"), "plan-process-a")
	if err != nil {
		t.Fatal(err)
	}
	lock, err := (recovery.LocalCandidateStorage{ExpectedUID: uint32(os.Geteuid())}).AcquireAuthorityLock(context.Background(), paths)
	if os.Getenv("VSK_RECOVERY_EXPECT_BLOCKED") == "1" {
		if err == nil {
			_ = lock.Close()
			t.Fatal("second recovery process acquired the authority lock")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}
