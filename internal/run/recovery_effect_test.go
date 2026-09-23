package run

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type recoveryAuthorityFixture struct {
	state  store.AuthorityState
	health store.Health
}

func (fixture recoveryAuthorityFixture) CurrentAuthority(context.Context) (store.AuthorityState, error) {
	return fixture.state, nil
}

func (fixture recoveryAuthorityFixture) Health(context.Context) (store.Health, error) {
	return fixture.health, nil
}

func recoveryCanaryBindingFixture() ExactStepBinding {
	digest := "sha256:" + strings.Repeat("a", 64)
	acknowledgement := "acknowledgement-a"
	plan := generated.Plan{PlanID: "plan-a", PlanDigest: digest, AuthorizationBranch: "human", ExecutorMode: "central", Binding: generated.PlanBinding{StateRevision: 19, RecoveryEpoch: 8}}
	run := generated.Run{RunID: "run-a", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, AcknowledgementID: &acknowledgement, ExecutorMode: "central", StateRevision: 19, RecoveryEpoch: 8}
	step := generated.RunStep{StepID: "step-a", OperationType: "recovery.canary.noop", AdapterID: "core.recovery", TargetID: "instance-new", InputDigest: digest, ArtifactDigest: digest, EffectState: "intent-recorded"}
	lease := generated.ExecutorLease{LeaseID: "lease-a", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RunID: run.RunID, StepID: step.StepID, ArtifactDigest: digest, RecoveryEpoch: 8, Status: "active"}
	return ExactStepBinding{Plan: plan, Run: run, Step: step, Lease: lease}
}

func TestRecoveryCanaryNoopRequiresExactRecoveryAuthority(t *testing.T) {
	binding := recoveryCanaryBindingFixture()
	fixture := recoveryAuthorityFixture{
		state:  store.AuthorityState{InstanceID: binding.Step.TargetID, RecoveryEpoch: binding.Run.RecoveryEpoch, Mode: "recovery-required"},
		health: store.Health{Revision: store.RevisionToken{StateRevision: binding.Run.StateRevision, RecoveryEpoch: binding.Run.RecoveryEpoch}, RecoveryPending: true, MutationEnabled: false},
	}
	effect, err := NewRecoveryEffect(fixture)
	if err != nil {
		t.Fatal(err)
	}
	result, err := effect.Execute(context.Background(), binding)
	if err != nil || result.Status != "succeeded" || result.Changed || !result.EffectObserved {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
	verified, err := effect.Verify(context.Background(), binding, result)
	if err != nil || !verified.Verified || verified.Digest != result.ResultDigest {
		t.Fatalf("verification = %#v, err = %v", verified, err)
	}

	for name, mutate := range map[string]func(*ExactStepBinding){
		"adapter":       func(value *ExactStepBinding) { value.Step.AdapterID = "fixture.recovery" },
		"operation":     func(value *ExactStepBinding) { value.Step.OperationType = "recovery.restore.cutover" },
		"authorization": func(value *ExactStepBinding) { value.Plan.AuthorizationBranch = "preauthorized" },
		"target":        func(value *ExactStepBinding) { value.Step.TargetID = "former-instance" },
		"epoch":         func(value *ExactStepBinding) { value.Run.RecoveryEpoch++ },
		"revision":      func(value *ExactStepBinding) { value.Run.StateRevision++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := binding
			mutate(&changed)
			if _, err := effect.Execute(context.Background(), changed); err == nil {
				t.Fatal("changed recovery canary binding accepted")
			}
		})
	}
}

func TestCoreRouterDispatchesOnlyExactRecoveryNoop(t *testing.T) {
	binding := recoveryCanaryBindingFixture()
	fixture := recoveryAuthorityFixture{
		state:  store.AuthorityState{InstanceID: binding.Step.TargetID, RecoveryEpoch: binding.Run.RecoveryEpoch, Mode: "recovery-required"},
		health: store.Health{Revision: store.RevisionToken{StateRevision: binding.Run.StateRevision, RecoveryEpoch: binding.Run.RecoveryEpoch}, RecoveryPending: true},
	}
	effect, _ := NewRecoveryEffect(fixture)
	router := CoreRouter{Recovery: effect}
	result, err := router.Execute(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if verified, err := router.Verify(context.Background(), binding, result); err != nil || !verified.Verified {
		t.Fatalf("verification = %#v, err = %v", verified, err)
	}
	binding.Step.OperationType = "recovery.restore.cutover"
	if _, err := router.Execute(context.Background(), binding); err == nil {
		t.Fatal("non-canary recovery operation dispatched")
	}
}
