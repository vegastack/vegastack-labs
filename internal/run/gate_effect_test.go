package run

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

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
