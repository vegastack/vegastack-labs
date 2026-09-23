//go:build linux

package store

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func openGateTestStore(t *testing.T) *GateRepository {
	t.Helper()
	configuration := testConfig(t)
	authority, err := Open(context.Background(), configuration)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := authority.Close(); err != nil {
			t.Error(err)
		}
	})
	return NewGateRepository(authority)
}

func gateDraftFixture(t *testing.T) GateDraftRequest {
	t.Helper()
	digest := "sha256:" + strings.Repeat("a", 64)
	return GateDraftRequest{
		EvidenceID: "evidence-a", GateID: "G-008", SubjectID: "site-a",
		DefinitionVersion: "1.0.0", EvaluatorVersion: "1.0.0", ArtifactDigest: digest,
		SourceKind: "local", ProofClass: "live",
		Bundle:    generated.GateEvidenceBundle{Schema: generated.SchemaIDGateEvidenceBundle, SchemaVersion: "1.1.0", Facts: []generated.GateEvidenceFact{}, Checks: []generated.GateEvidenceCheck{}, Attachments: []generated.GateEvidenceAttachment{}, CollectorID: "collector-a", ObservedAt: "2026-09-15T08:00:00Z"},
		Expected:  RevisionToken{StateRevision: 0, RecoveryEpoch: 0},
		KeyDigest: digest, RequestDigest: digest,
		Attribution: audit.Attribution{AuthenticatedPrincipalID: "human-a", AuthenticatedPrincipalMethod: "local"},
	}
}

func gateApplyFixture(draft GateDraft) GateApplyRequest {
	return GateApplyRequest{
		DraftID: draft.DraftID, EvidenceID: draft.EvidenceID, GateID: draft.GateID, SubjectID: draft.SubjectID,
		SourceKind: draft.SourceKind, ProofClass: draft.ProofClass, SupersedesEvidenceID: draft.SupersedesEvidenceID, RevokesEvidenceID: draft.RevokesEvidenceID,
		Expected: RevisionToken{StateRevision: draft.StateRevision, RecoveryEpoch: draft.RecoveryEpoch},
		PlanID:   "plan-a", PlanDigest: "sha256:" + strings.Repeat("b", 64),
		RunID: "run-a", StepID: "step-a", LeaseID: "lease-a",
		DeclarationID: "declaration-a", DeclarationRevision: 1,
		KeyDigest: "sha256:" + strings.Repeat("c", 64), RequestDigest: "sha256:" + strings.Repeat("d", 64),
		Attribution: audit.Attribution{AuthenticatedPrincipalID: "human-a", AuthenticatedPrincipalMethod: "local"},
	}
}

func TestGateDraftIsNotAppliedAndStaleApplyFails(t *testing.T) {
	repository := openGateTestStore(t)
	draft, err := repository.PutGateDraft(context.Background(), gateDraftFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := repository.ListAppliedGateEvidence(context.Background(), draft.GateID, draft.SubjectID)
	if err != nil || len(rows) != 0 {
		t.Fatalf("draft became authority: %d %v", len(rows), err)
	}
	request := gateApplyFixture(draft)
	request.Expected.StateRevision++
	if _, err := repository.ApplyGateEvidence(context.Background(), request); Code(err) != generated.ErrorCodePlanStale {
		t.Fatalf("stale apply: %v", err)
	}
}

func TestParallelGateDraftsSerializeAndHistoricalDraftIsImmutable(t *testing.T) {
	repository := openGateTestStore(t)
	requests := []GateDraftRequest{gateDraftFixture(t), gateDraftFixture(t)}
	requests[1].EvidenceID = "evidence-b"
	requests[1].KeyDigest = "sha256:" + strings.Repeat("b", 64)
	requests[1].RequestDigest = "sha256:" + strings.Repeat("b", 64)
	type result struct {
		draft GateDraft
		err   error
	}
	results := make([]result, 2)
	var workers sync.WaitGroup
	for index := range requests {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			results[index].draft, results[index].err = repository.PutGateDraft(context.Background(), requests[index])
		}(index)
	}
	workers.Wait()
	created, stale := 0, 0
	for _, result := range results {
		switch Code(result.err) {
		case "":
			if result.err != nil {
				t.Fatal(result.err)
			}
			created++
		case generated.ErrorCodeStateConflict:
			stale++
		default:
			t.Fatalf("unexpected parallel result: %v", result.err)
		}
	}
	if created != 1 || stale != 1 {
		t.Fatalf("created=%d stale=%d", created, stale)
	}
	var stored GateDraft
	for _, result := range results {
		if result.err == nil {
			stored = result.draft
		}
	}
	if _, err := repository.store.conn.ExecContext(context.Background(), `DELETE FROM gate_evidence_drafts WHERE draft_id=?`, stored.DraftID); err == nil {
		t.Fatal("historical draft deleted")
	}
	if _, err := repository.GetAppliedProfileScope(context.Background()); Code(err) != generated.ErrorCodeResourceNotFound {
		t.Fatalf("missing applied profile synthesized: %v", err)
	}
}

// seedGateExactStep creates synthetic Phase 4 durable records only inside the
// test database. Production evidence uses the real plan/run engine instead.
func seedGateExactStep(t *testing.T, repository *GateRepository, planID, planDigest, runID, stepID, leaseID, declarationID, targetID, artifactDigest, operationType string, revision int64) {
	t.Helper()
	db := repository.store.conn
	digest := "sha256:" + strings.Repeat("e", 64)
	now := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	expires := repository.store.config.Clock().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO declaration_revisions(declaration_id,declaration_revision,declaration_type,state_revision,recovery_epoch,content_digest,reason_digest,status,canonical_bytes,created_at,created_by,agent_session_id) VALUES(?,1,'gate',?,0,?,?,'committed',X'7B7D',?,'human-a','session-a')`, []any{declarationID, revision, digest, digest, now}},
		{`INSERT INTO immutable_plans(plan_id,plan_digest,declaration_id,declaration_revision,state_revision,recovery_epoch,observation_fingerprint,idempotency_key_digest,request_digest,canonical_bytes,readable_plan,readable_digest,created_at,expires_at) VALUES(?,?,?,1,?,0,?,?,?,X'7B7D','synthetic',?,?,?)`, []any{planID, planDigest, declarationID, revision, digest, gateDigest([]byte(planID)), digest, digest, now, expires}},
		{`INSERT INTO plan_runs(run_id,plan_id,plan_digest,authorization_decision_id,acknowledgement_id,policy_version,executor_mode,executor_id,executor_binding_digest,status,cancellation_requested,rollback_status,verification_status,verification_digest,changed,state_revision,recovery_epoch,submit_key_digest,request_digest,canonical_bytes,created_at,updated_at) VALUES(?,?,?,'decision-a',NULL,'1.0.0','central','executor-central',?,'running',0,'not-requested','pending',NULL,0,?,0,?,?,X'7B7D',?,?)`, []any{runID, planID, planDigest, digest, revision, gateDigest([]byte(runID)), digest, now, now}},
		{`INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,active_lease_id,result_digest,started_at,finished_at) VALUES(?,?,1,'operation-a',?,'core.gate','executor-central',?,?,?,1,'running','intent-recorded',?,NULL,?,NULL)`, []any{stepID, runID, operationType, targetID, artifactDigest, artifactDigest, leaseID, now}},
		{`INSERT INTO target_execution_leases(lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes,lease_kind,last_renewed_at,renewal_count) VALUES(?,?,?,?,?,?,0,?,?,?,?,'active',X'7B7D','central',NULL,0)`, []any{leaseID, runID, stepID, targetID, digest, gateDigest([]byte(leaseID)), now, now, expires, expires}},
	}
	for index, statement := range statements {
		if _, err := db.ExecContext(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(fmt.Errorf("seed statement %d: %w", index, err))
		}
	}
}

func TestExactAppliedProfileAndEvidenceAppendWithoutStatusEdits(t *testing.T) {
	repository := openGateTestStore(t)
	draft, err := repository.PutGateDraft(context.Background(), gateDraftFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	profile := ProfileApplyRequest{
		BindingID: "binding-a", Scope: GateAppliedProfile{ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0", Capabilities: []string{}},
		Expected: RevisionToken{StateRevision: draft.StateRevision, RecoveryEpoch: draft.RecoveryEpoch},
		PlanID:   "plan-profile", PlanDigest: "sha256:" + strings.Repeat("b", 64), RunID: "run-profile", StepID: "step-profile", LeaseID: "lease-profile", DeclarationID: "declaration-profile", DeclarationRevision: 1,
		KeyDigest: "sha256:" + strings.Repeat("b", 64), RequestDigest: "sha256:" + strings.Repeat("c", 64),
		Attribution: audit.Attribution{AuthenticatedPrincipalID: "human-a", AuthenticatedPrincipalMethod: "local"},
	}
	profileDraft, err := repository.PutProfileDraft(context.Background(), ProfileDraftRequest{BindingID: profile.BindingID, Scope: profile.Scope, Expected: profile.Expected, KeyDigest: "sha256:" + strings.Repeat("9", 64), RequestDigest: "sha256:" + strings.Repeat("8", 64), Attribution: profile.Attribution})
	if err != nil {
		t.Fatal(err)
	}
	profile.Expected.StateRevision = profileDraft.StateRevision
	seedGateExactStep(t, repository, profile.PlanID, profile.PlanDigest, profile.RunID, profile.StepID, profile.LeaseID, profile.DeclarationID, profile.Scope.ProfileID, profileDraft.ScopeDigest, "gate.profile.bind", profile.Expected.StateRevision)
	appliedScope, err := repository.ApplyProfileBinding(context.Background(), profile)
	if err != nil {
		t.Fatal(err)
	}
	repeatScope, err := repository.ApplyProfileBinding(context.Background(), profile)
	if err != nil || repeatScope.StateRevision != appliedScope.StateRevision {
		t.Fatalf("profile retry: %#v %v", repeatScope, err)
	}
	if appliedScope.StateRevision != 3 {
		t.Fatalf("profile revision %d", appliedScope.StateRevision)
	}
	apply := gateApplyFixture(draft)
	apply.Expected.StateRevision = appliedScope.StateRevision
	apply.PlanDigest = "sha256:" + strings.Repeat("d", 64)
	apply.ReleaseBuildID, apply.ToolVersion, apply.ExpiresAt = "release-a", "1.0.0", "2026-09-15T09:00:00Z"
	apply.SourceKind, apply.ProofClass = "local", "live"
	seedGateExactStep(t, repository, apply.PlanID, apply.PlanDigest, apply.RunID, apply.StepID, apply.LeaseID, apply.DeclarationID, apply.SubjectID, draft.BundleDigest, "gate.evidence.apply", apply.Expected.StateRevision)
	evidence, err := repository.ApplyGateEvidence(context.Background(), apply)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := repository.ApplyGateEvidence(context.Background(), apply)
	if err != nil || repeated.EvidenceID != evidence.EvidenceID || repeated.StateRevision != evidence.StateRevision {
		t.Fatalf("exact retry: %#v %v", repeated, err)
	}
	misbound := apply
	misbound.EvidenceID = "evidence-other"
	if _, err := repository.ApplyGateEvidence(context.Background(), misbound); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("same-key change accepted: %v", err)
	}
	if evidence.Status != "applied" || evidence.ProfileID != "vegastack-labs" || evidence.StateRevision != 4 {
		t.Fatalf("evidence %#v", evidence)
	}
	rows, err := repository.ListAppliedGateEvidence(context.Background(), draft.GateID, draft.SubjectID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %d %v", len(rows), err)
	}
	current, err := repository.ListCurrentAppliedGateEvidence(context.Background(), draft.GateID, draft.SubjectID)
	if err != nil || len(current) != 1 || current[0].EvidenceID != evidence.EvidenceID {
		t.Fatalf("current rows %#v %v", current, err)
	}
	if _, err := repository.store.conn.ExecContext(context.Background(), `UPDATE gate_applied_evidence SET status='revoked' WHERE evidence_id=?`, evidence.EvidenceID); err == nil {
		t.Fatal("direct status edit accepted")
	}
	if _, err := repository.store.conn.ExecContext(context.Background(), `DELETE FROM gate_applied_profiles WHERE binding_id=?`, profile.BindingID); err == nil {
		t.Fatal("applied profile deleted")
	}
	if _, err := repository.store.conn.ExecContext(context.Background(), `UPDATE target_execution_leases SET status='released' WHERE lease_id=?`, apply.LeaseID); err != nil {
		t.Fatal(err)
	}
	revokeDraft := gateDraftFixture(t)
	revokeDraft.EvidenceID = "evidence-revoke"
	revokeDraft.RevokesEvidenceID = &evidence.EvidenceID
	revokeDraft.Expected.StateRevision = evidence.StateRevision
	revokeDraft.KeyDigest = "sha256:" + strings.Repeat("f", 64)
	revokeDraft.RequestDigest = revokeDraft.KeyDigest
	second, err := repository.PutGateDraft(context.Background(), revokeDraft)
	if err != nil {
		t.Fatal(err)
	}
	revoke := gateApplyFixture(second)
	revoke.PlanID, revoke.RunID, revoke.StepID, revoke.LeaseID, revoke.DeclarationID = "plan-revoke", "run-revoke", "step-revoke", "lease-revoke", "declaration-revoke"
	revoke.PlanDigest = "sha256:" + strings.Repeat("f", 64)
	revoke.KeyDigest, revoke.RequestDigest = "sha256:"+strings.Repeat("9", 64), "sha256:"+strings.Repeat("8", 64)
	revoke.ReleaseBuildID, revoke.ToolVersion, revoke.ExpiresAt = "release-a", "1.0.0", "2026-09-15T09:00:00Z"
	revoke.Status = "revoked"
	seedGateExactStep(t, repository, revoke.PlanID, revoke.PlanDigest, revoke.RunID, revoke.StepID, revoke.LeaseID, revoke.DeclarationID, revoke.SubjectID, second.BundleDigest, "gate.evidence.revoke", revoke.Expected.StateRevision)
	record, err := repository.ApplyGateEvidence(context.Background(), revoke)
	if err != nil {
		t.Fatal(err)
	}
	rows, err = repository.ListAppliedGateEvidence(context.Background(), draft.GateID, draft.SubjectID)
	if err != nil || len(rows) != 2 || rows[0].Status != "applied" || record.Status != "revoked" || rows[1].RevokesEvidenceID == nil || *rows[1].RevokesEvidenceID != evidence.EvidenceID {
		t.Fatalf("append-only revoke: rows=%#v err=%v", rows, err)
	}
	current, err = repository.ListCurrentAppliedGateEvidence(context.Background(), draft.GateID, draft.SubjectID)
	if err != nil || len(current) != 0 {
		t.Fatalf("revoked evidence remained current: rows=%#v err=%v", current, err)
	}
}
