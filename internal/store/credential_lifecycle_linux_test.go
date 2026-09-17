//go:build linux

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const lifecycleFingerprint = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func stringPointer(value string) *string { return &value }

func int64PointerLifecycle(value int64) *int64 { return &value }

// ackMode selects how the seeded run's human acknowledgement is (or is not)
// present, so a single spine helper can drive both the successful path and the
// acknowledgement-denial paths of Finding F3.
type ackMode int

const (
	ackConsumed ackMode = iota
	ackAbsent
	ackUnconsumed
	ackWrongHuman
)

// credentialLifecyclePlan builds one valid, canonical human/central core.credential
// plan whose digests round-trip through decodeStoredPlan, matching validPlanStoreRequest.
func credentialLifecyclePlan(declarationID, targetID, fingerprint, action string, declRevision, stateRevision int64) (generated.Plan, []byte) {
	readable := "readable\n"
	readableSum := sha256.Sum256([]byte(readable))
	value := generated.Plan{
		Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", DeclarationID: declarationID,
		Binding:    generated.PlanBinding{RecoveryEpoch: 0, PriorStateRevision: stateRevision - 1, StateRevision: stateRevision, DeclarationRevision: declRevision, ObservationFingerprint: testDigest, TargetDigest: testDigest, ReasonDigest: testDigest, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0"},
		Operations: []generated.PlanOperation{{Sequence: 1, OperationID: "operation-a", OperationType: action, AdapterID: "core.credential", ExecutorID: "executor-central", TargetID: targetID, InputDigest: fingerprint, ArtifactDigest: fingerprint, Idempotent: true}},
		Status:     "planned", Risk: "routine", AuthorizationBranch: "human", ExecutorMode: "central",
		CreatedAt: "2026-09-12T18:30:00Z", ExpiresAt: "2026-09-12T19:00:00Z",
		ReadableDigest: "sha256:" + hex.EncodeToString(readableSum[:]), Extensions: []generated.ContractExtension{},
	}
	preimage, _ := json.Marshal(value)
	planSum := sha256.Sum256(preimage)
	value.PlanDigest = "sha256:" + hex.EncodeToString(planSum[:])
	value.PlanID = "plan-" + hex.EncodeToString(planSum[:16])
	canonical, _ := json.Marshal(value)
	return value, canonical
}

// seedCredentialLifecycleStep seeds one committed core.credential plan and its
// running run/step/lease inside the test database, plus (per mode) an approved
// human acknowledgement bound to that run. It returns the exact
// CredentialStageRequest the run engine would compose, so a store-level test
// exercises the real append spine rather than a fake repository. Production
// evidence is created by the plan/run engine, never by this helper.
func seedCredentialLifecycleStep(t *testing.T, repository *CredentialRepository, action credentialref.LifecycleAction, reference generated.CredentialReference, stateRevision int64, mode ackMode) CredentialStageRequest {
	t.Helper()
	db := repository.store.conn
	now := repository.store.config.Clock().UTC().Truncate(time.Second)
	nowText := now.Format(time.RFC3339)
	expires := now.Add(time.Hour).Format(time.RFC3339)
	digest := "sha256:" + hexRepeat("e", 64)
	human := "principal-test-1"
	declarationID := "declaration-a"
	fingerprint := reference.Fingerprint
	suffix := string(action) + "-" + strconv.FormatInt(stateRevision, 10)
	runID := "run-" + shortDigest(suffix+"-run")
	stepID := "step-" + shortDigest(suffix+"-step")
	leaseID := "lease-" + shortDigest(suffix+"-lease")
	ackID := "ack-" + shortDigest(suffix+"-ack")

	plan, canonical := credentialLifecyclePlan(declarationID, reference.TargetID, fingerprint, string(action), 1, stateRevision)

	// The authoritative revision counter must equal the effect's Expected token,
	// exactly as the run engine would have advanced it to this point.
	if _, err := db.ExecContext(context.Background(), `UPDATE system_meta SET state_revision=? WHERE id=1 AND recovery_epoch=0`, stateRevision); err != nil {
		t.Fatal(err)
	}

	// declaration_revisions is only present to satisfy the immutable_plans FK.
	if _, err := db.ExecContext(context.Background(), `INSERT OR IGNORE INTO declaration_revisions(declaration_id,declaration_revision,declaration_type,state_revision,recovery_epoch,content_digest,reason_digest,status,canonical_bytes,created_at,created_by,agent_session_id) VALUES(?,1,'credential',1,0,?,?,'committed',X'7B7D',?,?,'session-a')`, declarationID, digest, digest, nowText, human); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `INSERT INTO immutable_plans(plan_id,plan_digest,declaration_id,declaration_revision,state_revision,recovery_epoch,observation_fingerprint,idempotency_key_digest,request_digest,canonical_bytes,readable_plan,readable_digest,created_at,expires_at) VALUES(?,?,?,1,?,0,?,?,?,?,?,?,?,?)`, plan.PlanID, plan.PlanDigest, declarationID, stateRevision, gateDigest([]byte(plan.PlanID)), gateDigest([]byte(plan.PlanID+"-key")), digest, canonical, "readable\n", plan.ReadableDigest, nowText, expires); err != nil {
		t.Fatal(err)
	}

	var runAck any
	if mode != ackAbsent {
		ackHuman := human
		if mode == ackWrongHuman {
			ackHuman = "principal-other-1"
		}
		status := "approved"
		var consumed any
		if mode != ackUnconsumed {
			consumed = nowText
		}
		if _, err := db.ExecContext(context.Background(), `INSERT INTO acknowledgement_requests(acknowledgement_id,plan_id,plan_digest,target_digest,reason_digest,human_id,authority_id,nonce_digest,state_revision,recovery_epoch,expires_at,status,request_bytes,pending_bytes,created_at,decided_at,consumed_at) VALUES(?,?,?,?,?,?,'authority-a',?,?,0,?,?,X'7B7D',X'7B7D',?,?,?)`, ackID, plan.PlanID, plan.PlanDigest, digest, digest, ackHuman, gateDigest([]byte(ackID)), stateRevision, expires, status, nowText, nowText, consumed); err != nil {
			t.Fatal(err)
		}
		runAck = ackID
	}

	if _, err := db.ExecContext(context.Background(), `INSERT INTO plan_runs(run_id,plan_id,plan_digest,authorization_decision_id,acknowledgement_id,policy_version,executor_mode,executor_id,executor_binding_digest,status,cancellation_requested,rollback_status,verification_status,verification_digest,changed,state_revision,recovery_epoch,submit_key_digest,request_digest,canonical_bytes,created_at,updated_at) VALUES(?,?,?,'decision-a',?,'1.0.0','central','executor-central',?,'running',0,'not-requested','pending',NULL,0,?,0,?,?,X'7B7D',?,?)`, runID, plan.PlanID, plan.PlanDigest, runAck, digest, stateRevision, gateDigest([]byte(runID)), digest, nowText, nowText); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,active_lease_id,result_digest,started_at,finished_at) VALUES(?,?,1,'operation-a',?,'core.credential','executor-central',?,?,?,1,'running','intent-recorded',?,NULL,?,NULL)`, stepID, runID, string(action), reference.TargetID, fingerprint, fingerprint, leaseID, nowText); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `INSERT INTO target_execution_leases(lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes,lease_kind,last_renewed_at,renewal_count) VALUES(?,?,?,?,?,?,0,?,?,?,?,'active',X'7B7D','central',NULL,0)`, leaseID, runID, stepID, reference.TargetID, digest, gateDigest([]byte(leaseID)), nowText, nowText, expires, expires); err != nil {
		t.Fatal(err)
	}

	return CredentialStageRequest{
		Reference: reference, DeclarationID: declarationID, DeclarationRevision: 1,
		PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RunID: runID, StepID: stepID, LeaseID: leaseID, HumanID: human,
		Expected: RevisionToken{StateRevision: stateRevision, RecoveryEpoch: 0}, Attribution: validDeclarationStoreRequest().Attribution,
		KeyDigest: gateDigest([]byte(plan.PlanID + "-key")), RequestDigest: gateDigest([]byte(plan.PlanID + "-req")),
	}
}

func releaseLease(t *testing.T, repository *CredentialRepository, leaseID string) {
	t.Helper()
	if _, err := repository.store.conn.ExecContext(context.Background(), `UPDATE target_execution_leases SET status='released' WHERE lease_id=?`, leaseID); err != nil {
		t.Fatal(err)
	}
}

func hexRepeat(char string, count int) string {
	out := make([]byte, count)
	for i := range out {
		out[i] = char[0]
	}
	return string(out)
}

func shortDigest(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:6])
}

func stagedReference(stateRevision int64) generated.CredentialReference {
	return generated.CredentialReference{
		Schema: generated.SchemaIDCredentialReference, SchemaVersion: "1.1.0",
		ReferenceID: "reference-a", ConsumerID: "consumer-a", PurposeID: "deploy-a",
		TargetID: "service-a", ResolverID: "native-a", MaterialVersion: "version-a",
		Fingerprint: lifecycleFingerprint, Status: "staged", StateRevision: stateRevision + 1, RecoveryEpoch: 0,
		VerifiedConsumerIDs: []string{},
	}
}

func stageBinding() credentialref.LifecycleBinding {
	return credentialref.LifecycleBinding{
		OperationID: "operation-a", Action: credentialref.ActionStage, DraftID: stringPointer("draft-a"),
		ReferenceID: "reference-a", ConsumerIDs: []string{"consumer-a"}, MaterialVersion: "version-a",
		ResolverID: "native-a", TargetID: "service-a", CiphertextFingerprint: lifecycleFingerprint,
		StateRevision: 1, RecoveryEpoch: 0,
	}
}

func tableCount(t *testing.T, repository *CredentialRepository, table string) int {
	t.Helper()
	var count int
	if err := repository.store.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// TestCredentialLifecycleSpineStageThenActivate exercises the real draft→plan→
// ack→apply spine end to end: a committed core.credential plan, a consumed human
// acknowledgement, a running run/step/lease, an appended staged version, then a
// full all-consumer activation with a real positive and required-denied result.
func TestCredentialLifecycleSpineStageThenActivate(t *testing.T) {
	repository := openCredentialStore(t)

	stageRequest := seedCredentialLifecycleStep(t, repository, credentialref.ActionStage, stagedReference(2), 2, ackConsumed)
	staged, err := repository.ApplyCredentialLifecycle(context.Background(), CredentialLifecycleApplyRequest{Binding: stageBinding(), Stage: stageRequest})
	if err != nil {
		t.Fatalf("real stage spine failed: %v", err)
	}
	if staged.Status != "staged" || staged.StateRevision != 3 {
		t.Fatalf("stage appended wrong version: %+v", staged)
	}
	if tableCount(t, repository, "credential_reference_versions") != 1 {
		t.Fatal("staged version not appended")
	}
	releaseLease(t, repository, stageRequest.LeaseID)

	activatedAt := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	activeReference := stagedReference(3)
	activeReference.Status = "active"
	activeReference.ActivatedAt = &activatedAt
	activeReference.VerifiedConsumerIDs = []string{"consumer-a"}
	activateRequest := seedCredentialLifecycleStep(t, repository, credentialref.ActionActivate, activeReference, 3, ackConsumed)

	activateBinding := credentialref.LifecycleBinding{
		OperationID: "operation-a", Action: credentialref.ActionActivate, ReferenceID: "reference-a",
		ConsumerIDs: []string{"consumer-a"}, RequiredDeniedConsumerIDs: []string{"consumer-denied"},
		MaterialVersion: "version-a", ResolverID: "native-a", TargetID: "service-a",
		CiphertextFingerprint: lifecycleFingerprint, StateRevision: 3, RecoveryEpoch: 0,
	}
	verifications := []credentialref.ConsumerVerification{
		{ConsumerID: "consumer-a", ProfileID: "profile-a", RoleID: "role-a", MaterialVersion: "version-a", CiphertextFingerprint: lifecycleFingerprint, EvidenceDigest: testDigest, RestartObserved: true, Result: "verified", ReasonCode: "loaded"},
		{ConsumerID: "consumer-denied", ProfileID: "profile-b", RoleID: "role-b", MaterialVersion: "version-a", CiphertextFingerprint: lifecycleFingerprint, EvidenceDigest: testDigest, RestartObserved: false, Result: "denied", ReasonCode: "denied"},
	}
	active, err := repository.ApplyCredentialLifecycle(context.Background(), CredentialLifecycleApplyRequest{Binding: activateBinding, Stage: activateRequest, Verifications: verifications})
	if err != nil {
		t.Fatalf("real activate spine failed: %v", err)
	}
	if active.Status != "active" || active.StateRevision != 4 {
		t.Fatalf("activate appended wrong version: %+v", active)
	}
	if tableCount(t, repository, "credential_reference_versions") != 2 {
		t.Fatal("active version not appended")
	}
	if tableCount(t, repository, "credential_consumer_verifications") != 2 {
		t.Fatal("consumer verification evidence not appended atomically with the version")
	}
}

// TestCredentialLifecycleAppendRequiresConsumedAcknowledgement is Finding F3: an
// otherwise exact core.credential step whose run has no consumed human
// acknowledgement must not append any credential status, even from a direct
// in-process caller. Each denial variant leaves the reference and evidence
// tables empty, proving the append transaction is atomic (the version row is
// inserted before the acknowledgement proof and rolled back with it).
func TestCredentialLifecycleAppendRequiresConsumedAcknowledgement(t *testing.T) {
	for _, mode := range []ackMode{ackAbsent, ackUnconsumed, ackWrongHuman} {
		t.Run(strconv.Itoa(int(mode)), func(t *testing.T) {
			repository := openCredentialStore(t)
			stageRequest := seedCredentialLifecycleStep(t, repository, credentialref.ActionStage, stagedReference(2), 2, mode)
			if _, err := repository.ApplyCredentialLifecycle(context.Background(), CredentialLifecycleApplyRequest{Binding: stageBinding(), Stage: stageRequest}); Code(err) != generated.ErrorCodePrerequisiteBlocked {
				t.Fatalf("append admitted without a consumed human acknowledgement: %v", err)
			}
			for _, table := range []string{"credential_reference_versions", "credential_consumer_verifications", "credential_recovery_records"} {
				if count := tableCount(t, repository, table); count != 0 {
					t.Fatalf("table %s changed on an acknowledgement-blocked append: %d", table, count)
				}
			}
		})
	}
}

// TestCredentialLifecycleTablesRejectMutation proves the append-only guarantee by
// executing real UPDATE and DELETE statements against a genuinely inserted row in
// every new lifecycle table, not merely counting triggers.
func TestCredentialLifecycleTablesRejectMutation(t *testing.T) {
	repository := openCredentialStore(t)
	db := repository.store.conn
	now := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	inserts := []struct {
		table string
		query string
		args  []any
	}{
		{"credential_lifecycle_bindings", `INSERT INTO credential_lifecycle_bindings(binding_id,declaration_id,declaration_revision,operation_id,action,reference_id,binding_digest,binding_bytes,recovery_epoch,created_at) VALUES('binding-x','declaration-a',1,'operation-a','credential.stage','reference-a',?,X'7B7D',0,?)`, []any{testDigest, now}},
		{"credential_consumer_verifications", `INSERT INTO credential_consumer_verifications(verification_id,reference_id,version_id,consumer_id,profile_id,role_id,material_version,ciphertext_fingerprint,evidence_digest,restart_observed,result,reason_code,recovery_epoch,created_at) VALUES('verification-x','reference-a','version-x','consumer-a','profile-a','role-a','version-a',?,?,1,'verified','loaded',0,?)`, []any{testDigest, testDigest, now}},
		{"credential_recovery_records", `INSERT INTO credential_recovery_records(record_id,reference_id,version_id,draft_id,custody_proof_digest,former_controller_fence_digest,prior_recovery_epoch,recovery_epoch,evidence_digest,created_at) VALUES('record-x','reference-a','version-x','draft-a',?,?,0,1,?,?)`, []any{testDigest, testDigest, testDigest, now}},
	}
	for _, insert := range inserts {
		if _, err := db.ExecContext(context.Background(), insert.query, insert.args...); err != nil {
			t.Fatalf("seed %s: %v", insert.table, err)
		}
		if _, err := db.ExecContext(context.Background(), "UPDATE "+insert.table+" SET created_at='2000-01-01T00:00:00Z'"); err == nil {
			t.Fatalf("%s allowed an UPDATE", insert.table)
		}
		if _, err := db.ExecContext(context.Background(), "DELETE FROM "+insert.table); err == nil {
			t.Fatalf("%s allowed a DELETE", insert.table)
		}
		if count := tableCount(t, repository, insert.table); count != 1 {
			t.Fatalf("%s row changed despite append-only triggers: %d", insert.table, count)
		}
	}
}

// TestCredentialLifecycleRejectsForgedActionNullables keeps the structural
// action-nullability denials the domain binding enforces.
func TestCredentialLifecycleRejectsForgedActionNullables(t *testing.T) {
	repository := openCredentialStore(t)
	binding := stageBinding()
	binding.CustodyProofDigest = stringPointer(testDigest)
	request := seedCredentialLifecycleStep(t, repository, credentialref.ActionStage, stagedReference(2), 2, ackConsumed)
	if _, err := repository.ApplyCredentialLifecycle(context.Background(), CredentialLifecycleApplyRequest{Binding: binding, Stage: request}); Code(err) != generated.ErrorCodeInputInvalid {
		t.Fatalf("forged stage binding admitted: %v", err)
	}
	recover := stageBinding()
	recover.Action = credentialref.ActionRecover
	recover.PriorRecoveryEpoch = int64PointerLifecycle(0)
	recover.RecoveryEpoch = 0
	recover.CustodyProofDigest = stringPointer(testDigest)
	recover.FormerControllerFenceDigest = stringPointer(testDigest)
	if _, err := repository.ApplyCredentialLifecycle(context.Background(), CredentialLifecycleApplyRequest{Binding: recover, Stage: request}); Code(err) != generated.ErrorCodeInputInvalid {
		t.Fatalf("non-increasing recover epoch admitted: %v", err)
	}
}
