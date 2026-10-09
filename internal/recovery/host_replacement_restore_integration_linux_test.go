//go:build linux

package recovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/identity"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// External checkpoint, backup, and former-writer capabilities are synthetic in
// this software acceptance. SQLite, ownership transfer, candidate files, startup
// promotion, exact no-op execution, and authority enabling use production code.
func TestReplacementSnapshotPromotionAndCanary(t *testing.T) {
	principal := identity.Principal{ID: "restore-human", Method: identity.LocalOSPeerMethod}
	ctx := identity.WithVerifiedPrincipal(context.Background(), principal)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.db")
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	config := func(path string, mode store.OpenMode) store.Config {
		return store.Config{DatabasePath: path, Mode: mode, BusyTimeout: time.Second, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock}
	}
	authority, err := store.Open(ctx, config(path, store.InitializeNew))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = authority.Close() }()
	prior, err := authority.CurrentAuthority(ctx)
	if err != nil {
		t.Fatal(err)
	}
	binding := candidateTestBinding()
	binding.Source.RecoveryEpoch = prior.RecoveryEpoch
	binding.PriorRecoveryEpoch = prior.RecoveryEpoch
	binding.NextRecoveryEpoch = prior.RecoveryEpoch + 1
	binding.PriorInstanceID = prior.InstanceID
	// A real previous database contains one alias and the backed-up marker.
	rawDB := replacementRestoreDB(t, path)
	replacementRestoreExec(t, rawDB, `CREATE TABLE replacement_restore_marker(value TEXT NOT NULL) STRICT`)
	replacementRestoreExec(t, rawDB, `INSERT INTO replacement_restore_marker VALUES('backed-up-marker')`)
	q := seedReplacementRestoreHosts(t, rawDB, binding.Source)
	binding.FormerHostID = q.OldHostID
	binding.ReplacementHostID = q.NewHostID
	binding.RecoveryDraftID = q.Source.CustodyReferenceID
	binding.SourceAdmissionDigest = q.Source.CustodyBindingDigest
	first := store.HostAliasEvent{Ordinal: 1, Alias: q.AliasBindings[0], Execution: store.HostReplacementExecution{DraftID: "initial-claim"}, StateRevision: 1}
	replacementRestoreAlias(t, rawDB, first)
	if err := rawDB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(dir, "source.db")
	if err := copyCandidateTestFile(path, snapshot); err != nil {
		t.Fatal(err)
	}
	sourceDigest, err := candidateTestFileDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	authority, err = store.Open(ctx, config(path, store.OpenExisting))
	if err != nil {
		t.Fatal(err)
	}
	rawDB = replacementRestoreDB(t, path)
	replacementRestoreExec(t, rawDB, `UPDATE replacement_restore_marker SET value='newer-live-marker'`)
	d := store.HostReplacementDraft{Request: q, Digest: hostaction.Digest(q), BindingDigest: hostreplacement.BindingDigest(q)}
	d.ID = "host-replacement-" + d.Digest[7:39]
	x := store.HostReplacementExecution{ReplacementID: q.ReplacementID, DraftID: d.ID, PlanID: "freeze-plan", PlanDigest: hostaction.Digest("freeze-plan"), RunID: "freeze-run", StepID: "freeze-step", LeaseID: "freeze-lease"}
	frozen := first
	frozen.Ordinal = 2
	frozen.Alias.OwnerRevision++
	frozen.PreviousDigest = hostaction.Digest(first)
	frozen.ReplacementID = q.ReplacementID
	frozen.Execution = x
	replacementRestoreAlias(t, rawDB, frozen)
	unrelated := store.HostAliasEvent{Ordinal: 3, Alias: generated.HostReplacementAliasBinding{Schema: generated.SchemaIDHostReplacementAliasBinding, SchemaVersion: "1.0.0", AliasID: "unrelated-newer", OwnerHostID: "unrelated-host", OwnerIdentityDigest: hostaction.Digest("unrelated"), OwnerRevision: 1, OwnershipGeneration: 1}, Execution: store.HostReplacementExecution{DraftID: "unrelated-claim"}, StateRevision: 1}
	replacementRestoreAlias(t, rawDB, unrelated)
	state := generated.HostReplacementState{Schema: generated.SchemaIDHostReplacementState, SchemaVersion: "1.0.0", ReplacementID: q.ReplacementID, DeclarationID: d.ID, DeclarationRevision: 1, OldHostID: q.OldHostID, NewHostID: q.NewHostID, OldIdentityDigest: q.OldIdentityDigest, NewIdentityDigest: q.NewIdentityDigest, BindingDigest: d.BindingDigest, RoleBindingDigest: q.ProposedRoleBindingDigest, PriorOwnershipGeneration: 1, ProposedOwnershipGeneration: 2, AliasBindings: []generated.HostReplacementAliasBinding{frozen.Alias}, StateRevision: q.ExpectedStateRevision, RecoveryEpoch: q.RecoveryEpoch, Status: "frozen", RestorationClass: q.RestorationClass, NextAction: "resolve-fences", Blockers: []string{}}
	event := store.HostReplacementEvent{ReplacementID: q.ReplacementID, Sequence: 1, Type: "frozen", Execution: x, State: state, AuthorityDigest: hostaction.Digest("freeze-authority"), At: now.Format(time.RFC3339)}
	replacementRestoreExec(t, rawDB, `INSERT INTO host_replacement_drafts VALUES(?,?,?,?,?,?,?,?,?)`, d.ID, q.ReplacementID, q.Operation, d.BindingDigest, d.Digest, replacementRestoreJSON(q), principal.ID, q.ExpectedStateRevision, q.RecoveryEpoch)
	replacementRestoreExec(t, rawDB, `INSERT INTO host_replacement_events VALUES(?,?,?,?,?,?,?,?,?,?,?)`, q.ReplacementID, 1, "frozen", q.OldHostID, q.OldIdentityDigest, q.NewHostID, q.NewIdentityDigest, hostaction.Digest(event), replacementRestoreJSON(event), q.ExpectedStateRevision, q.RecoveryEpoch)
	if err := rawDB.Close(); err != nil {
		t.Fatal(err)
	}
	source := VerifiedSource{Binding: binding.Source, Snapshot: replacementRestoreSnapshot{fileSnapshotReader{path: snapshot, pointID: binding.PointID, digest: sourceDigest}}, DatabaseDigest: sourceDigest, Audit: AuditContinuity{IndependentCheckpointDigest: testCandidateDigest("9"), DecisionDigest: binding.AuditDecisionDigest}}
	request := replacementRestoreRequest(binding)
	health, err := authority.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request.ExpectedStateRevision = health.Revision.StateRevision
	guard := StoreReplacementContinuityGuard{Authority: authority, Replacements: store.NewHostReplacementRepository(authority)}
	ref, err := guard.PrepareReplacementContinuity(ctx, request, source)
	if err != nil {
		t.Fatalf("derive continuity: %v", err)
	}
	if ref == nil || ref.SourceAliasHighWatermark != 1 || ref.CurrentAliasHighWatermark != 3 {
		t.Fatalf("measured continuity=%+v", ref)
	}
	// A replacement process with an empty current journal cannot treat the
	// backed-up alias as evidence that continuity is unnecessary.
	missingPath := filepath.Join(t.TempDir(), "missing-current.db")
	if err := os.Chmod(filepath.Dir(missingPath), 0700); err != nil {
		t.Fatal(err)
	}
	missing, err := store.Open(ctx, config(missingPath, store.InitializeNew))
	if err != nil {
		t.Fatal(err)
	}
	missingGuard := StoreReplacementContinuityGuard{Authority: missing, Replacements: store.NewHostReplacementRepository(missing)}
	if _, err := missingGuard.PrepareReplacementContinuity(ctx, request, source); err == nil {
		t.Fatal("missing current continuity accepted backed-up aliases")
	}
	_ = missing.Close()
	request.ReplacementContinuity = ref
	request.CanaryBindingDigest, err = change.RestoreCanaryBindingDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	plans := store.NewPlanRepository(authority)
	restores := store.NewRestoreRepository(authority)
	planner := StoreRestorePlanner{Declarations: store.NewDeclarationRepository(authority), Plans: plans, Restores: restores, Clock: clock}
	binding, err = planner.CreateRestorePlan(ctx, request, source, FenceResult{Items: request.Fences, FenceSetDigest: request.FenceSetDigest}, source.Audit, principal)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	storedPlan, err := plans.GetPlan(ctx, binding.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	rawDB = replacementRestoreDB(t, path)
	replacementRestoreExec(t, rawDB, `INSERT INTO acknowledgement_requests(acknowledgement_id,plan_id,plan_digest,target_digest,reason_digest,human_id,authority_id,nonce_digest,state_revision,recovery_epoch,expires_at,status,request_bytes,pending_bytes,created_at,decided_at,consumed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'approved',?,?,?, ?,NULL)`, "restore-ack", binding.PlanID, binding.PlanDigest, binding.TargetDigest, storedPlan.Plan.Binding.ReasonDigest, principal.ID, "simulated-slack", hostaction.Digest("nonce"), storedPlan.Plan.Binding.StateRevision, binding.PriorRecoveryEpoch, storedPlan.Plan.ExpiresAt, []byte(`{}`), []byte(`{}`), storedPlan.Plan.CreatedAt, storedPlan.Plan.CreatedAt)
	_ = rawDB.Close()
	binding.HumanAcknowledgementID = "restore-ack"
	expected := store.RevisionToken{StateRevision: storedPlan.Plan.Binding.StateRevision, RecoveryEpoch: binding.PriorRecoveryEpoch}
	sessions := StoreRestoreSessions{Repository: restores}
	if err := sessions.CreateRestoreSession(ctx, binding, expected); err != nil {
		t.Fatalf("session: %v", err)
	}
	if err := sessions.TransitionRestore(ctx, binding, "planned", "fenced", binding.FenceSetDigest, expected); err != nil {
		t.Fatalf("fence transition: %v", err)
	}
	opener := func(ctx context.Context, p string) (*store.Store, error) {
		return store.Open(ctx, config(p, store.OpenExisting))
	}
	bundles := StoreRecoveryBundleStore{Authority: authority, Open: opener, Plans: plans, Restores: restores}
	manager := CandidateManager{DatabasePath: path, Storage: LocalCandidateStorage{ExpectedUID: uint32(os.Geteuid())}, Authority: StoreCandidateAuthority{Open: opener}, Bundles: bundles}
	stager := StoreCandidateStager{Manager: manager, Repository: restores, Plans: plans}
	receipt, err := stager.StageRestoreCandidate(ctx, binding, source, FenceResult{FenceSetDigest: binding.FenceSetDigest}, expected)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if receipt.BundleDigest == "" {
		t.Fatal("candidate omitted authority bundle")
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = manager.PromoteAtStartup(ctx, StartupExpectation{Binding: binding, DatabaseDigest: sourceDigest, JournalDigest: receipt.JournalDigest, BundleDigest: receipt.BundleDigest})
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	promoted, err := opener(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer promoted.Close()
	health, err = promoted.Health(ctx)
	if err != nil || !health.RecoveryPending || health.MutationEnabled {
		t.Fatalf("premature authority: %+v %v", health, err)
	}
	rawDB = replacementRestoreDB(t, path)
	defer rawDB.Close()
	var marker, owner, freeze string
	var revision int64
	if err := rawDB.QueryRow(`SELECT value FROM replacement_restore_marker`).Scan(&marker); err != nil || marker != "backed-up-marker" {
		t.Fatalf("marker %q: %v", marker, err)
	}
	if err := rawDB.QueryRow(`SELECT owner_host_id FROM host_alias_owners WHERE alias_id='unrelated-newer'`).Scan(&owner); err != nil || owner != "unrelated-host" {
		t.Fatalf("unrelated owner %q: %v", owner, err)
	}
	if err := rawDB.QueryRow(`SELECT owner_revision,frozen_replacement_id FROM host_alias_owners WHERE alias_id=?`, q.AliasBindings[0].AliasID).Scan(&revision, &freeze); err != nil || revision != 2 || freeze != q.ReplacementID {
		t.Fatalf("frozen authority %d %q: %v", revision, freeze, err)
	}
	promotedRestores := store.NewRestoreRepository(promoted)
	local := StoreRecoveryCanary{Authority: promoted, Restores: promotedRestores}
	effect, err := runengine.NewRecoveryEffect(promoted)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("restore plan revision=%d recovered revision=%d prior epoch=%d new epoch=%d", storedPlan.Plan.Binding.StateRevision, health.Revision.StateRevision, binding.PriorRecoveryEpoch, health.Revision.RecoveryEpoch)
	external := &canaryFixture{}
	canary := CanaryVerifier{Read: local, OldEpoch: local, Noop: BoundCanaryNoop{Restores: promotedRestores, Core: runengine.CoreRouter{Recovery: effect}, Recorder: promoted}, Audit: external, Backup: external, FormerWriter: external, Enable: local, Clock: clock}
	operations := OperationsService{config: OperationsConfig{Plans: StoreRestorePlanner{Plans: store.NewPlanRepository(promoted), Restores: promotedRestores}, Sessions: StoreRestoreSessions{Repository: promotedRestores}, Canary: canary}}
	verify := generated.RestoreVerifyRequest{Schema: generated.SchemaIDRestoreVerifyRequest, SchemaVersion: "1.1.0", PlanID: binding.PlanID, PlanDigest: binding.PlanDigest, PointID: binding.PointID, TargetDigest: binding.TargetDigest, FenceSetDigest: binding.FenceSetDigest, AuditDecisionDigest: binding.AuditDecisionDigest, CandidateDigest: binding.CandidateDigest, PriorInstanceID: binding.PriorInstanceID, NewInstanceID: binding.NewInstanceID, PriorRecoveryEpoch: binding.PriorRecoveryEpoch, NextRecoveryEpoch: binding.NextRecoveryEpoch, Source: binding.Source, ExpectedStateRevision: health.Revision.StateRevision}
	external.fail = "backup"
	if _, err := operations.Verify(ctx, verify, principal); err == nil {
		t.Fatal("incomplete canary enabled recovered authority")
	}
	if !slices.Contains(external.calls, "backup") {
		t.Fatalf("canary failed before simulated backup; external calls=%v", external.calls)
	}
	health, err = promoted.Health(ctx)
	if err != nil || !health.RecoveryPending || health.MutationEnabled {
		t.Fatalf("incomplete canary authority: %+v %v", health, err)
	}
	external.fail = ""
	result, err := operations.Verify(ctx, verify, principal)
	if err != nil || result.Status != "verified" {
		t.Fatalf("operations verify: %+v %v", result, err)
	}
	health, err = promoted.Health(ctx)
	if err != nil || health.RecoveryPending || !health.MutationEnabled {
		t.Fatalf("verified authority: %+v %v", health, err)
	}
	if _, _, err := promoted.RecoveryCanaryNoopEvent(ctx, binding.PlanID, binding.CanaryRunID); err != nil {
		t.Fatalf("actual no-op receipt missing: %v", err)
	}
}

func replacementRestoreDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}
func replacementRestoreExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}
func replacementRestoreJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
func replacementRestoreAlias(t *testing.T, db *sql.DB, e store.HostAliasEvent) {
	t.Helper()
	a := e.Alias
	var freeze any
	if e.ReplacementID != "" {
		freeze = e.ReplacementID
	}
	replacementRestoreExec(t, db, `INSERT INTO host_alias_history VALUES(?,?,?,?,?,?,?,?,?)`, e.Ordinal, a.AliasID, a.OwnerRevision, a.OwnerHostID, a.OwnerIdentityDigest, a.OwnershipGeneration, freeze, hostaction.Digest(e), replacementRestoreJSON(e))
	replacementRestoreExec(t, db, `INSERT INTO host_alias_owners VALUES(?,?,?,?,?,?,?) ON CONFLICT(alias_id) DO UPDATE SET owner_revision=excluded.owner_revision,event_digest=excluded.event_digest,frozen_replacement_id=excluded.frozen_replacement_id`, a.AliasID, a.OwnerHostID, a.OwnerIdentityDigest, a.OwnerRevision, a.OwnershipGeneration, hostaction.Digest(e), freeze)
}

func replacementRestoreRequest(binding generated.RestoreBinding) generated.RestoreRequest {
	fence := generated.RestoreFenceItem{Schema: generated.SchemaIDRestoreFenceItem, SchemaVersion: "1.1.0", Boundary: "host-service", SubjectID: "former-control", TargetID: "control-a", AdapterID: "adapter-a", FormerIdentityID: "former-identity",
		ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "recovery-policy", PolicyVersion: "1.0.0", ReleaseBuildID: "build-a", EvaluatorVersion: "1.0.0", RecoveryEpoch: binding.PriorRecoveryEpoch,
		RequiredEvidenceKinds: []string{"service-denied"}, Required: true, EvidenceIDs: []string{binding.SourceAdmissionDigest, binding.FenceQualificationDigest}, EvidenceDigest: binding.FenceSetDigest, Status: "required"}
	decision := generated.RestoreAuditDecision{Schema: generated.SchemaIDRestoreAuditDecision, SchemaVersion: "1.1.0", LocalLastEventID: 0, IndependentLastEventID: 0, IndependentCheckpointDigest: binding.AuditDecisionDigest, Strategy: "matched", DecisionDigest: binding.AuditDecisionDigest}
	return generated.RestoreRequest{Schema: generated.SchemaIDRestoreRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: binding.PriorRecoveryEpoch, RecoveryEpoch: binding.PriorRecoveryEpoch, TargetDigest: binding.TargetDigest, IdempotencyKey: "restore-plan-test", Source: binding.Source, Fences: []generated.RestoreFenceItem{fence}, AuditDecision: decision, PointID: binding.PointID, DependencyIDs: binding.DependencyIDs, TargetIDs: binding.TargetIDs, PriorInstanceID: binding.PriorInstanceID, NewInstanceID: binding.NewInstanceID, PriorRecoveryEpoch: binding.PriorRecoveryEpoch, NextRecoveryEpoch: binding.NextRecoveryEpoch, FenceSetDigest: binding.FenceSetDigest, AuditDecisionDigest: binding.AuditDecisionDigest, CandidateDigest: binding.CandidateDigest,
		FormerHostID: binding.FormerHostID, ReplacementHostID: binding.ReplacementHostID, RecoveryDraftID: binding.RecoveryDraftID, CiphertextFingerprint: binding.CiphertextFingerprint, SourceAdmissionDigest: binding.SourceAdmissionDigest, FenceQualificationDigest: binding.FenceQualificationDigest, RecoveryRunID: binding.RecoveryRunID, RecoveryStepID: binding.RecoveryStepID, RecoveryLeaseID: binding.RecoveryLeaseID, RecoveryChallengeID: binding.RecoveryChallengeID, RecoveryReceiptID: binding.RecoveryReceiptID, CanaryRunID: binding.CanaryRunID, CanaryStepID: binding.CanaryStepID, CanaryLeaseID: binding.CanaryLeaseID, CanaryChallengeID: binding.CanaryChallengeID, CanaryReceiptID: binding.CanaryReceiptID, CanaryBindingDigest: binding.CanaryBindingDigest}
}

// The external backup fixture exposes the same measured snapshot capability as
// localbackup; the watermark is read from digest-checked SQLite bytes, never supplied.
type replacementRestoreSnapshot struct{ fileSnapshotReader }

func (s replacementRestoreSnapshot) InspectHostAliasWatermark(ctx context.Context) (int64, error) {
	digest, err := candidateTestFileDigest(s.path)
	if err != nil {
		return 0, err
	}
	if digest != s.digest {
		return 0, os.ErrInvalid
	}
	u := url.URL{Scheme: "file", Path: s.path}
	q := u.Query()
	q.Set("mode", "ro")
	q.Set("immutable", "1")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var n int64
	err = db.QueryRowContext(ctx, `SELECT COALESCE(MAX(event_ordinal),0) FROM host_alias_history`).Scan(&n)
	return n, err
}
