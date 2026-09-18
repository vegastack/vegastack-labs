//go:build linux

package api

import (
	"context"
	"database/sql"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
	"time"
)

type lifecyclePublicPlanReader struct{ plans *planengine.Service }

// This verifier is confined to synthetic isolated acceptance. It qualifies
// persisted running intent and lease before returning material-free evidence.
type lifecyclePublicVerifier struct{ fixture *lifecyclePublicFixture }

func (verifier lifecyclePublicVerifier) VerifySecretStep(ctx context.Context, plan generated.Plan, operation generated.PlanOperation) error {
	db, err := sql.Open("sqlite3", "file:"+verifier.fixture.path+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	var count int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM plan_run_steps AS steps JOIN plan_runs AS runs ON runs.run_id=steps.run_id JOIN target_execution_leases AS leases ON leases.lease_id=steps.active_lease_id WHERE runs.plan_id=? AND runs.plan_digest=? AND runs.status='running' AND steps.operation_id=? AND steps.status='running' AND steps.effect_state='intent-recorded' AND leases.status='active'", plan.PlanID, plan.PlanDigest, operation.OperationID).Scan(&count)
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("synthetic gate requires exact persisted running lease")
	}
	return nil
}
func (verifier lifecyclePublicVerifier) Verify(ctx context.Context, step runengine.ExactStepBinding, binding credentialref.LifecycleBinding) ([]credentialref.ConsumerVerification, error) {
	if generated.ValidateExecutorLeaseBinding(step.Plan, step.Run, step.Lease) != nil || step.Step.Status != "running" || step.Step.EffectState != "intent-recorded" || binding.OperationID != step.Step.OperationID {
		return nil, errors.New("synthetic consumer requires exact running intent")
	}
	results := []credentialref.ConsumerVerification{}
	for _, group := range []struct {
		ids    []string
		result string
	}{{binding.ConsumerIDs, "verified"}, {binding.RequiredDeniedConsumerIDs, "denied"}} {
		for _, consumer := range group.ids {
			results = append(results, credentialref.ConsumerVerification{ConsumerID: consumer, ProfileID: "profile-test", RoleID: "role-test", MaterialVersion: binding.MaterialVersion, CiphertextFingerprint: binding.CiphertextFingerprint, EvidenceDigest: lifecyclePublicDigest("synthetic-" + consumer), RestartObserved: true, Result: group.result, ReasonCode: "fixture-observed"})
		}
	}
	return results, nil
}

func (reader lifecyclePublicPlanReader) Get(ctx context.Context, id string) (generated.Plan, error) {
	result, err := reader.plans.Get(ctx, id)
	return result.Plan, err
}
func (reader lifecyclePublicPlanReader) ValidateCurrent(ctx context.Context, plan generated.Plan) error {
	return reader.plans.ValidateCurrent(ctx, plan)
}

func (fixture *lifecyclePublicFixture) applyDraft(t *testing.T, submission generated.CredentialLifecycleSubmission, missingAck bool) (generated.Run, error) {
	t.Helper()
	ctx := context.Background()
	draft, err := store.NewDeclarationRepository(fixture.authority).GetRevision(ctx, submission.ChangeID, 1)
	if err != nil {
		t.Fatal(err)
	}
	observations, err := planengine.NewStateObservationReader(fixture.revisions)
	if err != nil {
		t.Fatal(err)
	}
	plans, err := planengine.NewService(planengine.Config{Repository: fixture.revisions, Observations: observations, Clock: fixture.clock, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "routine", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if err != nil {
		t.Fatal(err)
	}
	current, err := fixture.revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := observations.CurrentFingerprint(ctx, draft.DeclarationID, draft.Operations)
	if err != nil {
		t.Fatal(err)
	}
	created, err := plans.Create(ctx, planengine.AuthorScope{PrincipalID: fixture.principal.ID, PrincipalMethod: fixture.principal.Method, AgentSessionID: "session-public-lifecycle"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: draft.DeclarationID, DeclarationRevision: 1, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, ObservationFingerprint: fingerprint, IdempotencyKey: "plan-" + submission.OperationID, Extensions: draft.Extensions})
	if err != nil {
		t.Fatal(err)
	}
	plan := created.Plan
	binding, err := fixture.references.GetLifecycleBinding(ctx, plan, submission.OperationID)
	if err != nil || binding.StateRevision != plan.Binding.StateRevision {
		t.Fatalf("public draft commit seal: %+v %v", binding, err)
	}
	authorizer := authorization.NewEvaluator(store.NewEffectiveAuthorizationRepository(fixture.authority))
	approvals, err := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(fixture.authority), Plans: lifecyclePublicPlanReader{plans}, Authorizer: authorizer, Clock: fixture.clock})
	if err != nil {
		t.Fatal(err)
	}
	human := identity.Principal{ID: "human-lifecycle", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
	card, err := approvals.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "authority-lifecycle", Nonce: "nonce-" + submission.OperationID}, plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	expires, err := time.Parse(time.RFC3339, plan.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := approvals.Decide(ctx, acknowledgement.Candidate{Human: human, AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, Nonce: card.Nonce, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, ExpiresAt: expires, DecidedAt: fixture.clock()})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := authorizer.Authorize(ctx, human, authorization.Request{Action: authorization.ActionExecute, Target: authorization.Target{Capability: "plan.execute", ResourceKind: "plan-target", ResourceID: plan.Operations[0].TargetID}, Plan: &plan, Branches: []authorization.Branch{authorization.BranchHuman}})
	if err != nil || !decision.Allowed {
		t.Fatalf("real execute policy: %+v %v", decision, err)
	}
	branch := "human"
	projected := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-" + submission.OperationID, PrincipalID: human.ID, Action: "execute", TargetID: plan.Operations[0].TargetID, Allowed: decision.Allowed, Branch: &branch, ReasonCode: decision.ReasonCode, GrantRevision: decision.GrantRevision, RecoveryEpoch: decision.RecoveryEpoch, PlanDigest: decision.PlanDigest, DecidedAt: fixture.clock().Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	verifier := lifecyclePublicVerifier{fixture}
	core, err := runengine.NewCoreCredentialEffect(fixture.references, store.NewAcknowledgementRepository(fixture.authority), verifier, verifier, runengine.UnavailableCredentialRecoveryVerifier{}, fixture.clock)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(fixture.authority), Plans: plans, Admission: runengine.NewAdmissionGate(approvals, fixture.clock), Adapters: adapter.NewRegistry(), CredentialCore: core, Clock: fixture.clock, LeaseContext: func(ctx context.Context, _ time.Time) (context.Context, context.CancelFunc) {
		return context.WithCancel(ctx)
	}})
	if err != nil {
		t.Fatal(err)
	}
	request := runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RecoveryEpoch: plan.Binding.RecoveryEpoch, IdempotencyKey: "apply-" + submission.OperationID, Extensions: []generated.ContractExtension{}}, Authorization: projected, Acknowledgement: &proof, Attribution: audit.Attribution{AuthenticatedPrincipalID: fixture.principal.ID, AuthenticatedPrincipalMethod: fixture.principal.Method, ResponsibleHumanPrincipalID: &human.ID, Agent: &audit.AgentMetadata{Name: "codex", SessionID: "session-public-lifecycle"}}}
	if missingAck {
		request.Acknowledgement = nil
	}
	return engine.Submit(ctx, request)
}

func TestCredentialLifecyclePublicDraftPlanAckApplySpine(t *testing.T) {
	for _, missingAck := range []bool{false, true} {
		t.Run(map[bool]string{false: "allowed-stage", true: "missing-ack"}[missingAck], func(t *testing.T) {
			fixture := newLifecyclePublicFixture(t)
			imported := fixture.importDraft(t, "version-1")
			request := fixture.stageRequest(t, imported)
			submission, err := fixture.service.CreateDraft(context.Background(), request, fixture.principal)
			if err != nil {
				t.Fatal(err)
			}
			run, err := fixture.applyDraft(t, submission, missingAck)
			versions, readErr := fixture.references.ListCredentialVersions(context.Background(), request.ReferenceID, request.RecoveryEpoch)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if missingAck {
				if err == nil || len(versions) != 0 {
					t.Fatalf("missing acknowledgement appended versions: %+v %v %v", run, err, versions)
				}
				return
			}
			if err != nil || run.Status != "succeeded" || len(versions) != 1 || versions[0].Status != "staged" {
				t.Fatalf("public stage apply: %+v %v versions=%+v", run, err, versions)
			}
			request.Action = "credential.activate"
			request.DraftID = nil
			request.RequiredDeniedConsumerIDs = []string{"consumer-denied"}
			fixture.submitAndApply(t, request)
			imported = fixture.importDraft(t, "version-2")
			request = fixture.stageRequest(t, imported)
			fixture.submitAndApply(t, request)
			prior := "version-1"
			request.Action = "credential.rotate"
			request.PriorMaterialVersion = &prior
			request.RequiredDeniedConsumerIDs = []string{"consumer-denied"}
			request.OverlapSeconds = 60
			fixture.submitAndApply(t, request)
			active, err := fixture.references.GetActiveVersion(context.Background(), request.ReferenceID, request.RecoveryEpoch)
			if err != nil || active.MaterialVersion != "version-2" {
				t.Fatalf("rotation logical active: %+v %v", active, err)
			}
			request.Action = "credential.revoke"
			request.DraftID = nil
			request.MaterialVersion = prior
			request.PriorMaterialVersion = nil
			request.ConsumerIDs = []string{}
			request.RequiredDeniedConsumerIDs = []string{}
			request.OverlapSeconds = 0
			fixture.submitAndApply(t, request)
			active, err = fixture.references.GetActiveVersion(context.Background(), request.ReferenceID, request.RecoveryEpoch)
			if err != nil || active.MaterialVersion != "version-2" {
				t.Fatalf("prior revoke changed replacement: %+v %v", active, err)
			}
		})
	}
}

func (fixture *lifecyclePublicFixture) submitAndApply(t *testing.T, input generated.CredentialLifecycleRequest) {
	t.Helper()
	current, err := fixture.revisions.CurrentRevision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	input.ExpectedStateRevision = current.StateRevision
	input.RecoveryEpoch = current.RecoveryEpoch
	input.IdempotencyKey = "intent-" + input.Action + "-" + input.MaterialVersion
	input.TargetDigest = credentialref.LifecycleTargetDigest(input)
	submission, err := fixture.service.CreateDraft(context.Background(), input, fixture.principal)
	if err != nil {
		t.Fatal(err)
	}
	result, err := fixture.applyDraft(t, submission, false)
	if err != nil || result.Status != "succeeded" {
		t.Fatalf("public %s apply: %+v %v", input.Action, result, err)
	}
}
