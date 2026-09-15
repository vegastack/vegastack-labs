//go:build linux

package run

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestProfileDraftRemainsInertUntilExactHumanApprovedPlanRun(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 16, 2, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	authority, err := store.Open(ctx, store.Config{DatabasePath: filepath.Join(directory, "control.db"), Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "0.0.0-dev", BuildVersion: "development", Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := authority.Close(); err != nil {
			t.Error(err)
		}
	})
	repository := store.NewGateRepository(authority)
	principalID := "human-gate-test"
	attribution := audit.Attribution{AuthenticatedPrincipalID: principalID, AuthenticatedPrincipalMethod: identity.LocalOSPeerMethod}
	draft, err := repository.PutProfileDraft(ctx, store.ProfileDraftRequest{BindingID: "binding-gate-test", Scope: store.GateAppliedProfile{ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "policy-gate-test", PolicyVersion: "1.0.0", Capabilities: []string{}}, Expected: store.RevisionToken{}, KeyDigest: digest("profile-draft-key"), RequestDigest: digest("profile-draft-request"), Attribution: attribution})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetAppliedProfileScope(ctx); store.Code(err) != generated.ErrorCodeResourceNotFound {
		t.Fatalf("draft became applied: %v", err)
	}
	changeRequest, err := gate.BuildProfileChange(draft, store.RevisionToken{StateRevision: draft.StateRevision, RecoveryEpoch: draft.RecoveryEpoch})
	if err != nil {
		t.Fatal(err)
	}
	changes, err := change.NewService(store.NewDeclarationRepository(authority), clock)
	if err != nil {
		t.Fatal(err)
	}
	revised, err := changes.Revise(ctx, change.AuthorScope{PrincipalID: principalID, PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "session-gate-test"}, changeRequest)
	if err != nil {
		t.Fatal(err)
	}
	plansRepo := store.NewPlanRepository(authority)
	observations, err := planengine.NewStateObservationReader(plansRepo)
	if err != nil {
		t.Fatal(err)
	}
	plans, err := planengine.NewService(planengine.Config{Repository: plansRepo, Observations: observations, Clock: clock, PolicyVersion: "1.0.0", ToolVersion: "0.0.0-dev", ContractVersion: "1.0.0", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := observations.CurrentFingerprint(ctx, revised.Document.DeclarationID, revised.Document.Operations)
	if err != nil {
		t.Fatal(err)
	}
	created, err := plans.Create(ctx, planengine.AuthorScope{PrincipalID: principalID, PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "session-gate-test"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: revised.Document.DeclarationID, DeclarationRevision: revised.Document.Revision, ExpectedStateRevision: revised.Document.StateRevision, RecoveryEpoch: revised.Document.RecoveryEpoch, ObservationFingerprint: fingerprint, IdempotencyKey: "plan-gate-test", Extensions: []generated.ContractExtension{}})
	if err != nil {
		t.Fatal(err)
	}
	plan := created.Plan
	acksRepo := store.NewAcknowledgementRepository(authority)
	acks, err := acknowledgement.NewService(acknowledgement.Config{Repository: acksRepo, Plans: sqliteAcknowledgementPlanReader{plans: plans}, Authorizer: sqliteAcknowledgementAuthorizer{}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	human := identity.Principal{ID: principalID, Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
	card, err := acks.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "authority-gate-test", Nonce: "nonce-gate-test"}, plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := acks.Decide(ctx, acknowledgement.Candidate{Human: human, AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, Nonce: card.Nonce, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, ExpiresAt: parseTime(plan.ExpiresAt), DecidedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	core, err := NewCoreGateEffect(repository, acksRepo, "development", "0.0.0-dev", clock)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(Config{Repository: store.NewRunRepository(authority), Plans: plans, Admission: NewAdmissionGate(acks, clock), Adapters: adapter.NewRegistry(), Core: core, Clock: clock, IDs: &deterministicIDs{}, LeaseContext: sqliteTestLeaseContext})
	if err != nil {
		t.Fatal(err)
	}
	branch := string(authorization.BranchHuman)
	decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-gate-test", PrincipalID: principalID, Action: string(authorization.ActionExecute), TargetID: plan.Operations[0].TargetID, Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, RecoveryEpoch: plan.Binding.RecoveryEpoch, PlanDigest: plan.PlanDigest, DecidedAt: now.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	request := SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: digest("stale-gate-plan"), RecoveryEpoch: plan.Binding.RecoveryEpoch, IdempotencyKey: "submit-gate-test", Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: attribution}
	if _, err := engine.Submit(ctx, request); Code(err) != generated.ErrorCodePlanStale {
		t.Fatalf("stale run accepted: %v", err)
	}
	if _, err := repository.GetAppliedProfileScope(ctx); store.Code(err) != generated.ErrorCodeResourceNotFound {
		t.Fatalf("stale run applied profile: %v", err)
	}
	request.Reference.PlanDigest = plan.PlanDigest
	run, err := engine.Submit(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "succeeded" {
		t.Fatalf("run status %s", run.Status)
	}
	scope, err := repository.GetAppliedProfileScope(ctx)
	if err != nil || scope.ProfileID != "vegastack-labs" || scope.StateRevision != run.StateRevision+1 {
		t.Fatalf("applied scope %+v %v", scope, err)
	}
	current, err := plansRepo.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bundle := generated.GateEvidenceBundle{Schema: generated.SchemaIDGateEvidenceBundle, SchemaVersion: "1.1.0", Facts: []generated.GateEvidenceFact{}, Checks: []generated.GateEvidenceCheck{}, Attachments: []generated.GateEvidenceAttachment{}, CollectorID: "collector-gate-test", ObservedAt: now.Add(-time.Minute).Format(time.RFC3339)}
	evidenceDraft, err := repository.PutGateDraft(ctx, store.GateDraftRequest{EvidenceID: "evidence-gate-test", GateID: "platform-safety", SubjectID: "site-gate-test", DefinitionVersion: "1.0.0", EvaluatorVersion: "1.0.0", ArtifactDigest: digest("site-gate-target"), SourceKind: "fixture", ProofClass: "fixture", Bundle: bundle, Expected: current, KeyDigest: digest("evidence-draft-key"), RequestDigest: digest("evidence-draft-request"), Attribution: attribution})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := repository.ListAppliedGateEvidence(ctx, evidenceDraft.GateID, evidenceDraft.SubjectID)
	if err != nil || len(rows) != 0 {
		t.Fatalf("evidence draft became authority: %d %v", len(rows), err)
	}
	evidenceChange, err := gate.BuildEvidenceChange(evidenceDraft, store.RevisionToken{StateRevision: evidenceDraft.StateRevision, RecoveryEpoch: evidenceDraft.RecoveryEpoch})
	if err != nil {
		t.Fatal(err)
	}
	revisedEvidence, err := changes.Revise(ctx, change.AuthorScope{PrincipalID: principalID, PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "session-gate-test"}, evidenceChange)
	if err != nil {
		t.Fatal(err)
	}
	evidenceFingerprint, err := observations.CurrentFingerprint(ctx, revisedEvidence.Document.DeclarationID, revisedEvidence.Document.Operations)
	if err != nil {
		t.Fatal(err)
	}
	evidencePlanCommit, err := plans.Create(ctx, planengine.AuthorScope{PrincipalID: principalID, PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "session-gate-test"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: revisedEvidence.Document.DeclarationID, DeclarationRevision: revisedEvidence.Document.Revision, ExpectedStateRevision: revisedEvidence.Document.StateRevision, RecoveryEpoch: revisedEvidence.Document.RecoveryEpoch, ObservationFingerprint: evidenceFingerprint, IdempotencyKey: "plan-gate-evidence-test", Extensions: []generated.ContractExtension{}})
	if err != nil {
		t.Fatal(err)
	}
	evidencePlan := evidencePlanCommit.Plan
	evidenceCard, err := acks.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "authority-gate-test", Nonce: "nonce-gate-evidence"}, evidencePlan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	evidenceApproval, err := acks.Decide(ctx, acknowledgement.Candidate{Human: human, AuthorityID: evidenceCard.Request.AuthorityID, Action: acknowledgement.ActionApprove, PlanID: evidencePlan.PlanID, PlanDigest: evidencePlan.PlanDigest, TargetDigest: evidencePlan.Binding.TargetDigest, ReasonDigest: evidencePlan.Binding.ReasonDigest, Nonce: evidenceCard.Nonce, StateRevision: evidencePlan.Binding.StateRevision, RecoveryEpoch: evidencePlan.Binding.RecoveryEpoch, ExpiresAt: parseTime(evidencePlan.ExpiresAt), DecidedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	evidenceDecision := decision
	evidenceDecision.DecisionID, evidenceDecision.TargetID, evidenceDecision.PlanDigest = "decision-gate-evidence", evidencePlan.Operations[0].TargetID, evidencePlan.PlanDigest
	evidenceRunRequest := SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: evidencePlan.PlanID, PlanDigest: evidencePlan.PlanDigest, RecoveryEpoch: evidencePlan.Binding.RecoveryEpoch, IdempotencyKey: "submit-gate-evidence", Extensions: []generated.ContractExtension{}}, Authorization: evidenceDecision, Acknowledgement: &evidenceApproval, Attribution: attribution}
	evidenceRun, err := engine.Submit(ctx, evidenceRunRequest)
	if err != nil || evidenceRun.Status != "succeeded" {
		t.Fatalf("evidence run %s %v", evidenceRun.Status, err)
	}
	rows, err = repository.ListAppliedGateEvidence(ctx, evidenceDraft.GateID, evidenceDraft.SubjectID)
	if err != nil || len(rows) != 1 || rows[0].Status != "applied" || rows[0].ProofClass != "fixture" {
		t.Fatalf("applied rows %+v %v", rows, err)
	}
	resolved := gate.ResolvedScope{ProfileID: scope.ProfileID, ProfileVersion: scope.ProfileVersion, PolicyID: scope.PolicyID, PolicyVersion: scope.PolicyVersion, Capabilities: scope.Capabilities, StateRevision: scope.StateRevision, RecoveryEpoch: scope.RecoveryEpoch}
	subject := gate.Subject{ID: evidenceDraft.SubjectID, Kind: "site", ReleaseBuildID: "development", ToolVersion: "0.0.0-dev", DeclarationID: evidencePlan.DeclarationID, DeclarationRevision: evidencePlan.Binding.DeclarationRevision, ArtifactDigest: evidenceDraft.ArtifactDigest, StateRevision: rows[0].StateRevision}
	evaluation, err := gate.Evaluate(ctx, repository, resolved, subject, evidenceDraft.GateID, now, gate.NewProofRegistry())
	if err != nil || evaluation.Outcome == "passed" {
		t.Fatalf("fixture passed: %+v %v", evaluation, err)
	}
}
