package run

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type noAckGateRepository struct {
	GateRepository
	calls int
}

func (repo *noAckGateRepository) GetProfileDraft(_ context.Context, _ string) (store.ProfileDraft, error) {
	repo.calls++
	return store.ProfileDraft{}, nil
}

type fixedGateApproval struct {
	stored acknowledgement.Stored
	calls  int
}

func (source *fixedGateApproval) Get(_ context.Context, _ string) (acknowledgement.Stored, error) {
	source.calls++
	return source.stored, nil
}

func TestGateEffectRejectsMissingOrUnconsumedHumanAcknowledgementBeforeStore(t *testing.T) {
	now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	plan := testPlan(now)
	plan.AuthorizationBranch = "human"
	repo := &noAckGateRepository{}
	approval := &fixedGateApproval{}
	effect, err := NewCoreGateEffect(repo, approval, "build-a", "1.0.0", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	planDigest := plan.PlanDigest
	artifactDigest := plan.Operations[0].ArtifactDigest
	stepID, leaseID, runID := "step-a", "lease-a", "run-a"
	binding := ExactStepBinding{
		Plan:  plan,
		Run:   generated.Run{RunID: runID, ExecutorMode: "central", StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch},
		Step:  generated.RunStep{StepID: stepID, OperationType: "gate.profile.bind", OperationID: "binding-a", AdapterID: "core.gate", InputDigest: artifactDigest, ArtifactDigest: artifactDigest, EffectState: "intent-recorded"},
		Lease: generated.ExecutorLease{LeaseID: leaseID, Status: "active", StepID: stepID, RunID: runID, PlanID: plan.PlanID, PlanDigest: planDigest, ArtifactDigest: artifactDigest, RecoveryEpoch: plan.Binding.RecoveryEpoch},
	}
	for _, testCase := range []struct {
		name, branch      string
		acknowledgementID *string
		consumed          bool
		approvalCalls     int
	}{
		{name: "missing acknowledgement", branch: "human", acknowledgementID: nil, consumed: false, approvalCalls: 0},
		{name: "unconsumed acknowledgement", branch: "human", acknowledgementID: &leaseID, consumed: false, approvalCalls: 1},
		{name: "non-human branch", branch: "preauthorized", acknowledgementID: &leaseID, consumed: true, approvalCalls: 0},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			binding.Plan.AuthorizationBranch = testCase.branch
			binding.Run.AcknowledgementID = testCase.acknowledgementID
			approval.stored.Consumed = testCase.consumed
			approval.calls, repo.calls = 0, 0
			_, err := effect.Execute(context.Background(), binding)
			if Code(err) != generated.ErrorCodeApprovalRequired || repo.calls != 0 || approval.calls != testCase.approvalCalls {
				t.Fatalf("ack bypass: err=%v repoCalls=%d approvalCalls=%d", err, repo.calls, approval.calls)
			}
		})
	}
}

type orderingGateEffect struct {
	calls     int
	sawIntent bool
}

func (effect *orderingGateEffect) Execute(_ context.Context, binding ExactStepBinding) (adapter.Effect, error) {
	effect.calls++
	effect.sawIntent = binding.Step.EffectState == "intent-recorded" && binding.Lease.Status == "active" && binding.Plan.PlanID == binding.Run.PlanID
	return adapter.Effect{Status: "succeeded", ResultDigest: binding.Step.ArtifactDigest, Changed: true, EffectObserved: true}, nil
}

func (*orderingGateEffect) Verify(_ context.Context, _ ExactStepBinding, result adapter.Effect) (adapter.Verification, error) {
	return adapter.Verification{Verified: true, Digest: result.ResultDigest}, nil
}

func TestGateEffectNeverRunsBeforeExactAdmissionAndIntent(t *testing.T) {
	now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	plan := testPlan(now)
	plan.Operations[0].OperationType, plan.Operations[0].AdapterID, plan.Operations[0].InputDigest = "gate.evidence.apply", "core.gate", plan.Operations[0].ArtifactDigest
	repository := newMemoryRepository(plan)
	effect := &orderingGateEffect{}
	engine, err := NewEngine(Config{Repository: repository, Plans: repository, Admission: allowAdmission{}, Adapters: adapter.NewRegistry(), Core: effect, Clock: func() time.Time { return now }, IDs: &deterministicIDs{}, LeaseContext: testLeaseContext})
	if err != nil {
		t.Fatal(err)
	}
	branch := "preauthorized"
	request := SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: digest("wrong"), RecoveryEpoch: 0, IdempotencyKey: "gate-submit", Extensions: []generated.ContractExtension{}}, Authorization: generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-gate", PrincipalID: "policy-test", Action: "execute", TargetID: "target-test", Allowed: true, Branch: &branch, ReasonCode: "allowed", GrantRevision: 1, RecoveryEpoch: 0, PlanDigest: plan.PlanDigest, DecidedAt: now.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}}
	if _, err := engine.Submit(context.Background(), request); Code(err) != generated.ErrorCodePlanStale || effect.calls != 0 {
		t.Fatalf("stale admitted: calls=%d err=%v", effect.calls, err)
	}
	request.Reference.PlanDigest = plan.PlanDigest
	if _, err := engine.Submit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if effect.calls != 1 || !effect.sawIntent {
		t.Fatalf("gate called %d times before intent=%t", effect.calls, effect.sawIntent)
	}
}
