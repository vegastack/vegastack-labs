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
func seedCredentialLifecycleStep(t *testing.T, repository *CredentialRepository, action credentialref.LifecycleAction, reference generated.CredentialReference, stateRevision int64, mode ackMode, sealed ...credentialref.LifecycleBinding) CredentialStageRequest {
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

	if len(sealed) == 0 {
		binding := stageBinding()
		binding.Action = action
		binding.StateRevision = stateRevision
		binding.MaterialVersion = reference.MaterialVersion
		if action == credentialref.ActionActivate || action == credentialref.ActionRevoke {
			binding.DraftID = nil
			binding.ImportDraftStateRevision = nil
			binding.ImportDraftConsumerID = nil
			binding.ImportDraftPurposeID = nil
		}
		if action == credentialref.ActionActivate {
			binding.RequiredDeniedConsumerIDs = []string{"consumer-denied"}
		}
		sealed = []credentialref.LifecycleBinding{binding}
	}
	declRevision := int64(1)
	if len(sealed) > 0 {
		declarationID = "declaration-" + shortDigest(suffix)
		declRevision = 2
	}
	if action == credentialref.ActionStage || action == credentialref.ActionRotate || action == credentialref.ActionRecover {
		binding := stageBinding()
		if len(sealed) > 0 {
			binding = sealed[0]
		}
		if binding.DraftID != nil && binding.ImportDraftStateRevision != nil {
			if _, err := db.ExecContext(context.Background(), `INSERT INTO credential_import_drafts(draft_id,reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,idempotency_key_digest,request_digest,target_digest,ciphertext_name,ciphertext_fingerprint,state_revision,recovery_epoch,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?) ON CONFLICT DO NOTHING`, *binding.DraftID, reference.ReferenceID, reference.ConsumerID, reference.PurposeID, reference.TargetID, reference.ResolverID, reference.MaterialVersion, gateDigest([]byte(*binding.DraftID+"-key")), digest, testDigest, "ciphertext-a", fingerprint, *binding.ImportDraftStateRevision, human, nowText); err != nil {
				t.Fatal(err)
			}
		}
	}
	plan, canonical := credentialLifecyclePlan(declarationID, reference.TargetID, fingerprint, string(action), declRevision, stateRevision)
	if len(sealed) > 0 {
		binding := sealed[0]
		plan.Extensions = []generated.ContractExtension{{Name: "x-credential-lifecycle", ValueDigest: credentialref.LifecycleManifestDigestOf(binding)}}
		plan.PlanID, plan.PlanDigest = "", ""
		preimage, _ := json.Marshal(plan)
		sum := sha256.Sum256(preimage)
		plan.PlanDigest = "sha256:" + hex.EncodeToString(sum[:])
		plan.PlanID = "plan-" + hex.EncodeToString(sum[:16])
		canonical, _ = json.Marshal(plan)
		doc := validDeclarationStoreRequest().Document
		doc.DeclarationID = declarationID
		doc.Revision = 2
		doc.StateRevision = stateRevision
		doc.Status = "committed"
		doc.Extensions = plan.Extensions
		doc.Operations = []generated.DeclarationOperation{{Sequence: 1, OperationID: binding.OperationID, OperationType: string(binding.Action), AdapterID: "core.credential", TargetID: binding.TargetID, InputDigest: fingerprint, ArtifactDigest: fingerprint, Idempotent: true}}
		doc.ContentDigest = declarationContentDigest(doc, digest)
		body, _ := json.Marshal(doc)
		if _, err := db.ExecContext(context.Background(), `INSERT INTO declaration_revisions(declaration_id,declaration_revision,declaration_type,state_revision,recovery_epoch,content_digest,reason_digest,status,canonical_bytes,created_at,created_by,agent_session_id) VALUES(?,2,'credential',?,0,?,?,'committed',?,?,?,'session-a')`, declarationID, stateRevision, doc.ContentDigest, digest, body, nowText, human); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(binding)
		if _, err := db.ExecContext(context.Background(), `INSERT INTO credential_lifecycle_bindings(binding_id,declaration_id,declaration_revision,operation_id,action,reference_id,binding_digest,binding_bytes,recovery_epoch,created_at) VALUES(?,?,1,?,?,?,?,?,0,?)`, "binding-"+shortDigest(suffix), declarationID, binding.OperationID, string(binding.Action), binding.ReferenceID, credentialref.LifecycleManifestDigestOf(binding), raw, nowText); err != nil {
			t.Fatal(err)
		}
	}

	// The authoritative revision counter must equal the effect's Expected token,
	// exactly as the run engine would have advanced it to this point.
	if _, err := db.ExecContext(context.Background(), `UPDATE system_meta SET state_revision=? WHERE id=1 AND recovery_epoch=0`, stateRevision); err != nil {
		t.Fatal(err)
	}

	// declaration_revisions is only present to satisfy the immutable_plans FK.
	if _, err := db.ExecContext(context.Background(), `INSERT OR IGNORE INTO declaration_revisions(declaration_id,declaration_revision,declaration_type,state_revision,recovery_epoch,content_digest,reason_digest,status,canonical_bytes,created_at,created_by,agent_session_id) VALUES(?,1,'credential',1,0,?,?,'committed',X'7B7D',?,?,'session-a')`, declarationID, digest, digest, nowText, human); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `INSERT INTO immutable_plans(plan_id,plan_digest,declaration_id,declaration_revision,state_revision,recovery_epoch,observation_fingerprint,idempotency_key_digest,request_digest,canonical_bytes,readable_plan,readable_digest,created_at,expires_at) VALUES(?,?,?,?,?,0,?,?,?,?,?,?,?,?)`, plan.PlanID, plan.PlanDigest, declarationID, declRevision, stateRevision, gateDigest([]byte(plan.PlanID)), gateDigest([]byte(plan.PlanID+"-key")), digest, canonical, "readable\n", plan.ReadableDigest, nowText, expires); err != nil {
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
		Reference: reference, DeclarationID: declarationID, DeclarationRevision: declRevision,
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
		TargetID: "service-a", ResolverID: "fixture-resolver", MaterialVersion: "version-a",
		Fingerprint: lifecycleFingerprint, Status: "staged", StateRevision: stateRevision + 1, RecoveryEpoch: 0,
		VerifiedConsumerIDs: []string{},
	}
}

func stageBinding() credentialref.LifecycleBinding {
	return credentialref.LifecycleBinding{
		OperationID: "operation-a", Action: credentialref.ActionStage, DraftID: stringPointer("draft-a"),
		ReferenceID: "reference-a", ConsumerIDs: []string{"consumer-a"}, MaterialVersion: "version-a",
		ResolverID: "fixture-resolver", TargetID: "service-a", CiphertextFingerprint: lifecycleFingerprint,
		StateRevision: 2, RecoveryEpoch: 0, ImportDraftStateRevision: int64PointerLifecycle(1), ImportDraftConsumerID: stringPointer("consumer-a"), ImportDraftPurposeID: stringPointer("deploy-a"),
	}
}

// The native identity map is plan metadata, not proof that a consumer loaded
// bytes. This checks only the exact SQLite plan/append boundary.
func TestNativeMappingPlanSealRejectsChangedReaderUID(t *testing.T) {
	repository := openCredentialStore(t)
	binding := stageBinding()
	binding.Action = credentialref.ActionActivate
	binding.DraftID = nil
	binding.ImportDraftStateRevision = nil
	binding.ImportDraftConsumerID = nil
	binding.ImportDraftPurposeID = nil
	binding.RequiredDeniedConsumerIDs = []string{"consumer-denied"}
	binding.ResolverID = "native-systemd"
	binding.NativeArtifactConsumerID = "consumer-a"
	binding.NativeConsumers = []credentialref.NativeConsumerBinding{{ConsumerID: "consumer-a", TargetID: "service-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UnitName: "alpha.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a", LoadedName: credentialref.LoadedNameForVersion("consumer-a", binding.ReferenceID, binding.MaterialVersion)}}
	binding.NativeDeniedReaders = []credentialref.NativeDeniedReaderBinding{{ConsumerID: "consumer-denied", TargetID: "service-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-b", RoleID: "role-b"}}
	binding.StateRevision = 2
	if !credentialref.ValidLifecycleBinding(binding) {
		t.Fatal("native fixture must carry a complete exact map")
	}
	reference := stagedReference(2)
	reference.ResolverID = "native-systemd"
	stage := seedCredentialLifecycleStep(t, repository, credentialref.ActionActivate, reference, 2, ackConsumed, binding)
	if _, err := repository.store.conn.ExecContext(context.Background(), `INSERT INTO credential_reference_versions(version_id,reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,fingerprint,status,state_revision,recovery_epoch,activated_at,verified_consumers_bytes,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,created_at) VALUES('origin-a','reference-a','consumer-a','deploy-a','service-a','native-systemd','version-a',?,'staged',1,0,NULL,X'5B5D','declaration-a',1,?,?,?,?,?,'principal-test-1','2026-09-12T18:30:00Z')`, lifecycleFingerprint, stage.PlanID, stage.PlanDigest, stage.RunID, stage.StepID, stage.LeaseID); err != nil {
		t.Fatal(err)
	}
	tx, err := repository.store.conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireExactLifecycleBinding(context.Background(), tx, CredentialLifecycleApplyRequest{Binding: binding, Stage: stage}); err != nil {
		t.Fatalf("sealed native map rejected: %v", err)
	}
	mutated := binding
	mutated.NativeDeniedReaders = append([]credentialref.NativeDeniedReaderBinding(nil), binding.NativeDeniedReaders...)
	mutated.NativeDeniedReaders[0].ReaderUID++
	if err := requireExactLifecycleBinding(context.Background(), tx, CredentialLifecycleApplyRequest{Binding: mutated, Stage: stage}); Code(err) != generated.ErrorCodeIntegrityFailure {
		t.Fatalf("changed physical reader identity passed plan/CAS: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	// A later version with the same public reference and material version must
	// invalidate the old plan's staged artifact origin before append.
	if _, err := repository.store.conn.ExecContext(context.Background(), `INSERT INTO credential_reference_versions(version_id,reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,fingerprint,status,state_revision,recovery_epoch,activated_at,verified_consumers_bytes,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,created_at) SELECT 'origin-substituted',reference_id,'consumer-other',purpose_id,target_id,resolver_id,material_version,fingerprint,status,2,recovery_epoch,activated_at,verified_consumers_bytes,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,created_at FROM credential_reference_versions WHERE version_id='origin-a'`); err != nil {
		t.Fatal(err)
	}
	tx, err = repository.store.conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := requireExactLifecycleBinding(context.Background(), tx, CredentialLifecycleApplyRequest{Binding: binding, Stage: stage}); Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("substituted staged artifact origin passed plan/CAS: %v", err)
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
		MaterialVersion: "version-a", ResolverID: "fixture-resolver", TargetID: "service-a",
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

func TestCredentialLifecycleAppendRejectsDeniedEvidenceForOldMaterial(t *testing.T) {
	repository := openCredentialStore(t)
	stageRequest := seedCredentialLifecycleStep(t, repository, credentialref.ActionStage, stagedReference(2), 2, ackConsumed)
	if _, err := repository.ApplyCredentialLifecycle(context.Background(), CredentialLifecycleApplyRequest{Binding: stageBinding(), Stage: stageRequest}); err != nil {
		t.Fatal(err)
	}
	releaseLease(t, repository, stageRequest.LeaseID)

	activatedAt := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	reference := stagedReference(3)
	reference.Status = "active"
	reference.ActivatedAt = &activatedAt
	reference.VerifiedConsumerIDs = []string{"consumer-a"}
	request := seedCredentialLifecycleStep(t, repository, credentialref.ActionActivate, reference, 3, ackConsumed)
	binding := stageBinding()
	binding.Action = credentialref.ActionActivate
	binding.DraftID = nil
	binding.ImportDraftStateRevision = nil
	binding.ImportDraftConsumerID = nil
	binding.ImportDraftPurposeID = nil
	binding.StateRevision = 3
	binding.RequiredDeniedConsumerIDs = []string{"consumer-denied"}
	positive, err := credentialref.NewConsumerVerification(binding, "consumer-a", "profile-a", "role-a", testDigest, "loaded", "verified", true)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := credentialref.NewConsumerVerification(binding, "consumer-denied", "profile-b", "role-b", testDigest, "reader-denied", "denied", false)
	if err != nil {
		t.Fatal(err)
	}
	denied.MaterialVersion = "version-old"
	if _, err := repository.ApplyCredentialLifecycle(context.Background(), CredentialLifecycleApplyRequest{Binding: binding, Stage: request, Verifications: []credentialref.ConsumerVerification{positive, denied}}); err == nil {
		t.Fatal("denied evidence from an old material version activated")
	}
	if tableCount(t, repository, "credential_reference_versions") != 1 || tableCount(t, repository, "credential_consumer_verifications") != 0 {
		t.Fatal("failed activation appended a version or evidence row")
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

// TestCredentialEvidenceSQLRejectsNonCanonicalFields proves the database
// boundary rejects values that are length-correct but not lowercase hex, even
// if a future caller skips the Go constructor.
func TestCredentialEvidenceSQLRejectsNonCanonicalFields(t *testing.T) {
	for _, test := range []struct {
		name, statement string
		args            []any
	}{
		{
			name:      "consumer evidence digest",
			statement: `INSERT INTO credential_consumer_verifications(verification_id,reference_id,version_id,consumer_id,profile_id,role_id,material_version,ciphertext_fingerprint,evidence_digest,restart_observed,result,reason_code,recovery_epoch,created_at) VALUES('verification-bad-digest','reference-a','version-a','consumer-a','profile-a','role-a','material-a',?,?,1,'verified','loaded',0,'2026-09-22T00:00:00Z')`,
			args:      []any{lifecycleFingerprint, "sha256:" + hexRepeat("z", 64)},
		},
		{
			name:      "consumer ciphertext fingerprint",
			statement: `INSERT INTO credential_consumer_verifications(verification_id,reference_id,version_id,consumer_id,profile_id,role_id,material_version,ciphertext_fingerprint,evidence_digest,restart_observed,result,reason_code,recovery_epoch,created_at) VALUES('verification-bad-fingerprint','reference-a','version-a','consumer-a','profile-a','role-a','material-a',?,?,1,'verified','loaded',0,'2026-09-22T00:00:00Z')`,
			args:      []any{"sha256:" + hexRepeat("z", 64), testDigest},
		},
		{
			name:      "consumer reason code",
			statement: `INSERT INTO credential_consumer_verifications(verification_id,reference_id,version_id,consumer_id,profile_id,role_id,material_version,ciphertext_fingerprint,evidence_digest,restart_observed,result,reason_code,recovery_epoch,created_at) VALUES('verification-bad-reason','reference-a','version-a','consumer-a','profile-a','role-a','material-a',?,?,1,'verified','Bad Reason',0,'2026-09-22T00:00:00Z')`,
			args:      []any{lifecycleFingerprint, testDigest},
		},
		{
			name:      "recovery custody digest",
			statement: `INSERT INTO credential_recovery_records(record_id,reference_id,version_id,draft_id,custody_proof_digest,former_controller_fence_digest,prior_recovery_epoch,recovery_epoch,evidence_digest,created_at) VALUES('record-bad-custody','reference-a','version-a','draft-a',?,?,0,1,?,'2026-09-22T00:00:00Z')`,
			args:      []any{"sha256:" + hexRepeat("z", 64), testDigest, testDigest},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := openCredentialStore(t)
			if _, err := repository.store.conn.ExecContext(context.Background(), test.statement, test.args...); err == nil {
				t.Fatal("non-canonical credential evidence passed SQLite CHECK")
			}
		})
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

func TestLifecycleBindingStoreRoundtripAndTamperDenial(t *testing.T) {
	for _, mode := range []string{"roundtrip", "bytes-tamper", "digest-tamper"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			repository := openCredentialStore(t)
			binding := stageBinding()
			binding.StateRevision = 3 // declaration + inert binding + plan commits
			manifest := credentialref.LifecycleManifestDigestOf(binding)
			request := validDeclarationStoreRequest()
			request.Document.DeclarationType = "credential.lifecycle"
			request.Document.Operations = []generated.DeclarationOperation{{Sequence: 1, OperationID: binding.OperationID, OperationType: string(binding.Action), AdapterID: "core.credential", TargetID: binding.TargetID, InputDigest: binding.CiphertextFingerprint, ArtifactDigest: binding.CiphertextFingerprint, Idempotent: false}}
			request.Document.Extensions = []generated.ContractExtension{{Name: "x-credential-lifecycle", ValueDigest: manifest}}
			request.Document.ContentDigest = declarationContentDigest(request.Document, request.ReasonDigest)
			draft, err := NewDeclarationRepository(repository.store).CreateRevision(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			_, err = repository.PutLifecycleDraft(ctx, CredentialLifecycleDraftRequest{DeclarationID: draft.Document.DeclarationID, DeclarationRevision: draft.Document.Revision, Binding: binding, Expected: RevisionToken{StateRevision: 1}, Attribution: request.Attribution, KeyDigest: gateDigest([]byte("binding-key")), RequestDigest: gateDigest([]byte("binding-request"))})
			if err != nil {
				t.Fatal(err)
			}
			planRequest := validPlanStoreRequest(draft.Document)
			planRequest.Expected.StateRevision = 2
			planRequest.DesiredDeclaration.StateRevision = 3
			planRequest.Plan.Binding.PriorStateRevision = 2
			planRequest.Plan.Binding.StateRevision = 3
			planRequest.Plan.Extensions = request.Document.Extensions
			planRequest.Plan.Operations = []generated.PlanOperation{{Sequence: 1, OperationID: binding.OperationID, OperationType: string(binding.Action), AdapterID: "core.credential", ExecutorID: "executor-central", TargetID: binding.TargetID, InputDigest: binding.CiphertextFingerprint, ArtifactDigest: binding.CiphertextFingerprint, Idempotent: false}}
			planRequest.Plan.PlanID, planRequest.Plan.PlanDigest = "", ""
			preimage, _ := json.Marshal(planRequest.Plan)
			sum := sha256.Sum256(preimage)
			planRequest.Plan.PlanDigest = "sha256:" + hex.EncodeToString(sum[:])
			planRequest.Plan.PlanID = "plan-" + hex.EncodeToString(sum[:16])
			planRequest.CanonicalBytes, _ = json.Marshal(planRequest.Plan)
			planned, err := NewPlanRepository(repository.store).CommitDeclarationAndPlan(ctx, planRequest)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "roundtrip" {
				// Model privileged persisted-data corruption; production append-only
				// triggers are separately proven. The reader must still fail closed.
				if _, err := repository.store.conn.ExecContext(ctx, `DROP TRIGGER credential_lifecycle_bindings_no_update`); err != nil {
					t.Fatal(err)
				}
				if mode == "bytes-tamper" {
					changed := binding
					changed.CiphertextFingerprint = testDigest
					body, _ := json.Marshal(changed)
					_, err = repository.store.conn.ExecContext(ctx, `UPDATE credential_lifecycle_bindings SET binding_bytes=?`, body)
				} else {
					_, err = repository.store.conn.ExecContext(ctx, `UPDATE credential_lifecycle_bindings SET binding_digest=?`, testDigest)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			loaded, err := repository.GetLifecycleBinding(ctx, planned.Plan, binding.OperationID)
			if mode == "roundtrip" {
				if err != nil || loaded.Digest() != binding.Digest() {
					t.Fatalf("persisted binding roundtrip failed: %+v %v", loaded, err)
				}
			} else if Code(err) != generated.ErrorCodeIntegrityFailure {
				t.Fatalf("corrupt persisted binding admitted: %+v %v", loaded, err)
			}
		})
	}
}

func TestLifecycleVersionModelRotateThenRevokeKeepsV2Current(t *testing.T) {
	for _, revokePrior := range []bool{false, true} {
		t.Run(strconv.FormatBool(revokePrior), func(t *testing.T) {

			repository := openCredentialStore(t)
			state := int64(2)
			inertOnly := false
			apply := func(action credentialref.LifecycleAction, version string, prior *string) (generated.CredentialReference, error) {
				ref := stagedReference(state)
				ref.MaterialVersion = version
				binding := stageBinding()
				binding.Action = action
				binding.MaterialVersion = version
				binding.DraftID = stringPointer("draft-" + version)
				binding.StateRevision = state
				binding.PriorMaterialVersion = prior
				var checks []credentialref.ConsumerVerification
				if action == credentialref.ActionActivate || action == credentialref.ActionRotate {
					stamp := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
					ref.Status = "active"
					ref.ActivatedAt = &stamp
					ref.VerifiedConsumerIDs = []string{"consumer-a"}
					binding.RequiredDeniedConsumerIDs = []string{"consumer-denied"}
					checks = []credentialref.ConsumerVerification{
						{ConsumerID: "consumer-a", ProfileID: "profile-a", RoleID: "role-a", MaterialVersion: version, CiphertextFingerprint: lifecycleFingerprint, EvidenceDigest: testDigest, RestartObserved: true, Result: "verified", ReasonCode: "loaded"},
						{ConsumerID: "consumer-denied", ProfileID: "profile-b", RoleID: "role-b", MaterialVersion: version, CiphertextFingerprint: lifecycleFingerprint, EvidenceDigest: testDigest, Result: "denied", ReasonCode: "denied"},
					}
				}
				if action == credentialref.ActionActivate || action == credentialref.ActionRevoke {
					binding.DraftID = nil
					binding.ImportDraftStateRevision = nil
					binding.ImportDraftConsumerID = nil
					binding.ImportDraftPurposeID = nil
				}
				if action == credentialref.ActionRevoke {
					ref.Status = "revoked"
					binding.ConsumerIDs = nil
				}
				request := seedCredentialLifecycleStep(t, repository, action, ref, state, ackConsumed, binding)
				if inertOnly {
					releaseLease(t, repository, request.LeaseID)
					state++
					return generated.CredentialReference{}, nil
				}
				result, err := repository.ApplyCredentialLifecycle(context.Background(), CredentialLifecycleApplyRequest{Binding: binding, Stage: request, Verifications: checks})
				releaseLease(t, repository, request.LeaseID)
				state++
				return result, err
			}
			mustApply := func(action credentialref.LifecycleAction, version string, prior *string) {
				t.Helper()
				if _, err := apply(action, version, prior); err != nil {
					t.Fatalf("%s %s: %v", action, version, err)
				}
			}
			assertCurrent := func(want string) {
				t.Helper()
				got, err := repository.GetReference(context.Background(), "reference-a")
				if err != nil || got.MaterialVersion != want || got.Status != "active" {
					t.Fatalf("logical active version must be%s, got%+v err%v", want, got, err)
				}
			}
			mustApply(credentialref.ActionStage, "version-1", nil)
			mustApply(credentialref.ActionActivate, "version-1", nil)
			mustApply(credentialref.ActionStage, "version-2", nil)
			assertCurrent("version-1")
			// A planned rotation and its inert binding cannot select a replacement.
			inertOnly = true
			mustApply(credentialref.ActionRotate, "version-2", stringPointer("version-1"))
			inertOnly = false
			assertCurrent("version-1")
			before := tableCount(t, repository, "credential_reference_versions")
			if _, err := apply(credentialref.ActionActivate, "version-2", nil); Code(err) != generated.ErrorCodePrerequisiteBlocked {
				t.Fatalf("direct activation while v1active mustfail: %v", err)
			}
			if tableCount(t, repository, "credential_reference_versions") != before {
				t.Fatal("denied direct activation appended status")
			}
			mustApply(credentialref.ActionRotate, "version-2", stringPointer("version-1"))
			// The durable version append proves lineage even when no effect receipt or
			// successful run exists: model reconciliation marking that interrupted run partial.
			if _, err := repository.store.conn.ExecContext(context.Background(), `UPDATE plan_runs SET status='partial' WHERE plan_id=(SELECT plan_id FROM credential_reference_versions WHERE material_version='version-2' AND status='active' ORDER BY state_revision DESC LIMIT 1)`); err != nil {
				t.Fatal(err)
			}
			assertCurrent("version-2")
			prior, err := repository.GetCredentialVersion(context.Background(), "reference-a", "version-1")
			if err != nil || prior.Status != "active" {
				t.Fatalf("rotation must preserve exact prior status during overlap: %+v %v", prior, err)
			}
			if revokePrior {
				mustApply(credentialref.ActionRevoke, "version-1", nil)
			}
			assertCurrent("version-2")
			mustApply(credentialref.ActionRevoke, "version-2", nil)
			if _, err := repository.GetActiveVersion(context.Background(), "reference-a", 0); Code(err) != generated.ErrorCodeResourceNotFound {
				t.Fatalf("revoking replacement must not resurrect superseded prior: %v", err)
			}
			// A damaged append row cannot qualify as verified historical lineage.
			if _, err := repository.store.conn.ExecContext(context.Background(), `DROP TRIGGER credential_reference_versions_no_update`); err != nil {
				t.Fatal(err)
			}
			if _, err := repository.store.conn.ExecContext(context.Background(), `UPDATE credential_reference_versions SET target_id='wrong-target' WHERE material_version='version-2' AND status='active'`); err != nil {
				t.Fatal(err)
			}
			if _, err := repository.GetActiveVersion(context.Background(), "reference-a", 0); Code(err) != generated.ErrorCodeIntegrityFailure {
				t.Fatalf("corrupted applied lineage must fail integrity: %v", err)
			}

		})
	}
}

func TestLogicalActiveSelectorRejectsUnrelatedMultipleActiveVersions(t *testing.T) {
	repository := openCredentialStore(t)
	stage := seedCredentialLifecycleStep(t, repository, credentialref.ActionStage, stagedReference(2), 2, ackConsumed)
	if _, err := repository.ApplyCredentialLifecycle(context.Background(), CredentialLifecycleApplyRequest{Binding: stageBinding(), Stage: stage}); err != nil {
		t.Fatal(err)
	}
	releaseLease(t, repository, stage.LeaseID)
	ref := stagedReference(3)
	ref.Status = "active"
	stamp := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	ref.ActivatedAt = &stamp
	ref.VerifiedConsumerIDs = []string{"consumer-a"}
	binding := stageBinding()
	binding.Action = credentialref.ActionActivate
	binding.DraftID = nil
	binding.ImportDraftStateRevision = nil
	binding.ImportDraftConsumerID = nil
	binding.ImportDraftPurposeID = nil
	binding.StateRevision = 3
	binding.RequiredDeniedConsumerIDs = []string{"consumer-denied"}
	request := seedCredentialLifecycleStep(t, repository, credentialref.ActionActivate, ref, 3, ackConsumed)
	checks := []credentialref.ConsumerVerification{
		{ConsumerID: "consumer-a", ProfileID: "profile-a", RoleID: "role-a", MaterialVersion: ref.MaterialVersion, CiphertextFingerprint: ref.Fingerprint, EvidenceDigest: testDigest, RestartObserved: true, Result: "verified", ReasonCode: "loaded"},
		{ConsumerID: "consumer-denied", ProfileID: "profile-b", RoleID: "role-b", MaterialVersion: ref.MaterialVersion, CiphertextFingerprint: ref.Fingerprint, EvidenceDigest: testDigest, Result: "denied", ReasonCode: "denied"},
	}
	if _, err := repository.ApplyCredentialLifecycle(context.Background(), CredentialLifecycleApplyRequest{Binding: binding, Stage: request, Verifications: checks}); err != nil {
		t.Fatal(err)
	}
	// Model privileged persisted-data corruption with an unrelated active version;
	// the reader must reject ambiguity even when its metadata passes the schema.
	if _, err := repository.store.conn.ExecContext(context.Background(), `INSERT INTO credential_reference_versions(version_id,reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,fingerprint,status,state_revision,recovery_epoch,activated_at,verified_consumers_bytes,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,created_at) SELECT 'version-unrelated',reference_id,consumer_id,purpose_id,target_id,resolver_id,'version-unrelated',fingerprint,status,state_revision+1,recovery_epoch,activated_at,verified_consumers_bytes,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,created_at FROM credential_reference_versions WHERE status='active' LIMIT 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetActiveVersion(context.Background(), "reference-a", 0); Code(err) != generated.ErrorCodeIntegrityFailure {
		t.Fatalf("unrelated multiple active versions must fail closed: %v", err)
	}
	if _, err := repository.GetReference(context.Background(), "reference-a"); Code(err) != generated.ErrorCodeIntegrityFailure {
		t.Fatalf("logical current cannot mask ambiguity: %v", err)
	}
}

func TestLifecycleAppendRejectsSubstitutedDraftOrigin(t *testing.T) {
	for _, mode := range []string{"missing-id", "wrong-origin-revision", "wrong-consumer", "wrong-purpose"} {
		t.Run(mode, func(t *testing.T) {
			repository := openCredentialStore(t)
			binding := stageBinding()
			request := seedCredentialLifecycleStep(t, repository, credentialref.ActionStage, stagedReference(2), 2, ackConsumed, binding)
			switch mode {
			case "missing-id":
				binding.DraftID = stringPointer("missing-draft")
			case "wrong-origin-revision":
				binding.ImportDraftStateRevision = int64PointerLifecycle(2)
			case "wrong-consumer":
				binding.ImportDraftConsumerID = stringPointer("consumer-other")
				binding.ConsumerIDs = []string{"consumer-other"}
			case "wrong-purpose":
				binding.ImportDraftPurposeID = stringPointer("purpose-other")
			}
			if _, err := repository.ApplyCredentialLifecycle(context.Background(), CredentialLifecycleApplyRequest{Binding: binding, Stage: request}); err == nil {
				t.Fatal("substituted immutable draft origin must not append")
			}
			if tableCount(t, repository, "credential_reference_versions") != 0 {
				t.Fatal("origin denial must roll back version append")
			}
		})
	}
}

func TestLifecycleAppendRechecksImmutableDraftMetadata(t *testing.T) {
	cases := map[string]any{"draft_id": "wrong-draft", "reference_id": "wrong-reference", "consumer_id": "wrong-consumer", "purpose_id": "wrong-purpose", "target_id": "wrong-target", "resolver_id": "wrong-resolver", "material_version": "wrong-version", "ciphertext_fingerprint": testDigest, "state_revision": int64(9), "recovery_epoch": int64(9)}
	for field, value := range cases {
		t.Run(field, func(t *testing.T) {
			repository := openCredentialStore(t)
			binding := stageBinding()
			request := seedCredentialLifecycleStep(t, repository, credentialref.ActionStage, stagedReference(2), 2, ackConsumed, binding)
			if _, err := repository.store.conn.ExecContext(context.Background(), `DROP TRIGGER credential_import_drafts_no_update`); err != nil {
				t.Fatal(err)
			}
			if _, err := repository.store.conn.ExecContext(context.Background(), `PRAGMA ignore_check_constraints=ON`); err != nil {
				t.Fatal(err)
			}
			// field comes from the closed literal test table, never caller input.
			if _, err := repository.store.conn.ExecContext(context.Background(), "UPDATE credential_import_drafts SET "+field+"=? WHERE draft_id='draft-a'", value); err != nil {
				t.Fatal(err)
			}
			if _, err := repository.ApplyCredentialLifecycle(context.Background(), CredentialLifecycleApplyRequest{Binding: binding, Stage: request}); err == nil {
				t.Fatal("damaged immutable origin metadata must not append")
			}
			if tableCount(t, repository, "credential_reference_versions") != 0 {
				t.Fatal("origin mismatch must be atomic")
			}
		})
	}
}
