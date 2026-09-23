package run

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type syntheticGateVerifier struct {
	calls int
	deny  bool
}

func (gate *syntheticGateVerifier) VerifySecretStep(context.Context, generated.Plan, generated.PlanOperation) error {
	gate.calls++
	if gate.deny {
		return runError(generated.ErrorCodePrerequisiteBlocked, "synthetic-gate-denied")
	}
	return nil
}

type syntheticCredentialAdapter struct {
	calls            int
	plain            int
	observed         []byte
	retained         []byte
	secretReferences []adapter.SecretReference
}

func (implementation *syntheticCredentialAdapter) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	implementation.plain++
	return adapter.Effect{Status: "succeeded", ResultDigest: digest("synthetic-plain-effect"), EffectObserved: true}, nil
}
func (implementation *syntheticCredentialAdapter) ExecuteWithCredentials(_ context.Context, operation adapter.Operation, values []*credentialref.Value) (adapter.Effect, error) {
	implementation.calls++
	implementation.retained = values[0].Bytes()
	implementation.observed = append([]byte(nil), implementation.retained...)
	implementation.secretReferences = append([]adapter.SecretReference(nil), operation.SecretReferences...)
	return adapter.Effect{Status: "succeeded", ResultDigest: digest("synthetic-credential-effect"), EffectObserved: true}, nil
}
func (implementation *syntheticCredentialAdapter) Verify(context.Context, adapter.Operation, adapter.Effect) (adapter.Verification, error) {
	return adapter.Verification{Verified: true, Digest: digest("synthetic-credential-verification")}, nil
}

func TestSecretEffectJITOrderingAndZeroization(t *testing.T) {
	fixture := newEngineFixture(t)
	now := fixture.engine.clock().UTC()
	plan := fixture.store.plan
	plan.ExecutorMode, plan.AuthorizationBranch = "central", "human"
	plan.Binding.StateRevision = 3
	binding := credentialref.StepBinding{OperationID: plan.Operations[0].OperationID, AdapterID: plan.Operations[0].AdapterID, TargetID: plan.Operations[0].TargetID, ReferenceID: "ref-a", ConsumerID: plan.Operations[0].AdapterID, PurposeID: "deploy-a", MaterialVersion: "version-a", ResolverID: "native-a", StateRevision: 3, RecoveryEpoch: 0}
	plan.Operations[0].InputDigest = credentialref.OperationManifestDigest([]credentialref.StepBinding{binding}, binding.OperationID)
	plan.Extensions = []generated.ContractExtension{{Name: "x-credential-bindings", ValueDigest: credentialref.ManifestDigest([]credentialref.StepBinding{binding})}}
	plainOperation := plan.Operations[0]
	plainOperation.Sequence = 2
	plainOperation.OperationID = "operation-plain"
	plainOperation.InputDigest = digest("plain-operation-input")
	plan.Operations = append(plan.Operations, plainOperation)
	fixture.store.plan = plan
	fixture.request.Authorization.Branch = &plan.AuthorizationBranch
	fixture.request.Authorization.PlanDigest = plan.PlanDigest
	fixture.request.Reference.PlanDigest = plan.PlanDigest
	fixture.request.Acknowledgement = &generated.Acknowledgement{AcknowledgementID: "synthetic-approved-test-only"}
	activeAt := now.Format(time.RFC3339)
	bindings := &fakeCredentialBindings{binding: binding, reference: generated.CredentialReference{ReferenceID: binding.ReferenceID, ConsumerID: binding.ConsumerID, PurposeID: binding.PurposeID, TargetID: binding.TargetID, ResolverID: binding.ResolverID, MaterialVersion: binding.MaterialVersion, Status: "active", StateRevision: 2, RecoveryEpoch: 0, ActivatedAt: &activeAt, VerifiedConsumerIDs: []string{binding.ConsumerID}}}
	resolver := &countingCredentialResolver{}
	gate := &syntheticGateVerifier{}
	implementation := &syntheticCredentialAdapter{}
	registry := adapter.NewRegistry()
	if err := registry.Register(plan.Operations[0].AdapterID, implementation); err != nil {
		t.Fatal(err)
	}
	resolverRegistry := &fakeCredentialRegistry{resolver: resolver}
	engine, err := NewEngine(Config{Repository: fixture.store, Plans: fixture.store, Admission: allowAdmission{}, Adapters: registry, SecretGate: gate, CredentialStep: &CredentialStep{Bindings: bindings, Resolvers: resolverRegistry, Profiles: fakeCredentialProfiles{scope: store.GateAppliedProfile{ProfileID: "profile-a", StateRevision: 2, RecoveryEpoch: 0, Capabilities: []string{"credential.native.read"}}}, Plans: &fakeCredentialPlanValidator{}, Clock: func() time.Time { return now }}, Clock: fixture.engine.clock, IDs: fixture.engine.ids, LeaseContext: fixture.engine.leaseContext})
	if err != nil {
		t.Fatal(err)
	}
	intentCount := 0
	engine.testAfterBoundary = func(boundary Boundary) error {
		if boundary == BoundaryIntentRecorded {
			intentCount++
		}
		if boundary == BoundaryIntentRecorded && intentCount == 1 && (gate.calls != 0 || resolver.calls != 0) {
			t.Fatal("gate or resolver before durable intent")
		}
		return nil
	}
	result, err := engine.Submit(context.Background(), fixture.request)
	if err != nil || result.Status != "succeeded" || gate.calls != 1 || resolver.calls != 1 || implementation.calls != 1 || implementation.plain != 1 {
		t.Fatalf("JIT result=%s gate=%d resolver=%d credential=%d plain=%d err=%v", result.Status, gate.calls, resolver.calls, implementation.calls, implementation.plain, err)
	}
	for _, value := range implementation.retained {
		if value != 0 {
			t.Fatal("credential buffer remained after adapter effect")
		}
	}
	if string(implementation.observed) != "synthetic-private-canary" {
		t.Fatal("credential was not delivered to exact adapter")
	}
	if len(implementation.secretReferences) != 1 || implementation.secretReferences[0] != (adapter.SecretReference{ID: binding.ReferenceID, Consumer: binding.ConsumerID}) {
		t.Fatalf("adapter did not receive server-derived credential references: %#v", implementation.secretReferences)
	}
	gate.deny = true
	fixture.request.Reference.IdempotencyKey = "synthetic-gate-denied"
	deniedRun, deniedErr := engine.Submit(context.Background(), fixture.request)
	if Code(deniedErr) != generated.ErrorCodePrerequisiteBlocked || deniedRun.Status != "failed" || resolver.calls != 1 || implementation.calls != 1 {
		t.Fatalf("blocked gate reached resolver/effect: run=%s resolver=%d effects=%d err=%v", deniedRun.Status, resolver.calls, implementation.calls, deniedErr)
	}
	gate.deny = false
	lateTime := now
	lateResolver := &advancingCredentialResolver{advance: func() { lateTime = now.Add(2 * time.Minute) }}
	resolverRegistry.resolver = lateResolver
	engine.credentialStep.Clock = func() time.Time { return lateTime }
	fixture.request.Reference.IdempotencyKey = "synthetic-lease-expired-after-read"
	lateRun, lateErr := engine.Submit(context.Background(), fixture.request)
	if Code(lateErr) != generated.ErrorCodeInterrupted || lateRun.Status != "failed" || implementation.calls != 1 {
		t.Fatalf("late resolver reached adapter or claimed success: run=%s effects=%d err=%v", lateRun.Status, implementation.calls, lateErr)
	}
	for _, byteValue := range lateResolver.retained {
		if byteValue != 0 {
			t.Fatal("late resolver left borrowed bytes")
		}
	}
}

type leakingCredentialExecutor struct{ retained []byte }

func (implementation *leakingCredentialExecutor) ExecuteWithCredentials(_ context.Context, _ adapter.Operation, values []*credentialref.Value) (adapter.Effect, error) {
	implementation.retained = values[0].Bytes()
	return adapter.Effect{}, errors.New("synthetic-private-canary")
}

func TestCredentialEffectSanitizesAdapterErrorAndClosesBorrowedBytes(t *testing.T) {
	value, err := credentialref.NewValue([]byte("synthetic-private-canary"))
	if err != nil {
		t.Fatal(err)
	}
	implementation := &leakingCredentialExecutor{}
	_, err = invokeCredentialEffect(context.Background(), implementation, adapter.Operation{}, adapter.ExactExecutionBinding{}, []*credentialref.Value{value})
	if Code(err) != generated.ErrorCodeExecutionFailed || strings.Contains(err.Error(), "synthetic-private-canary") {
		t.Fatalf("unsanitized credential effect error: %v", err)
	}
	for _, byteValue := range implementation.retained {
		if byteValue != 0 {
			t.Fatal("borrowed bytes survived failing effect")
		}
	}
}

type panickingCredentialExecutor struct{ retained []byte }

func (implementation *panickingCredentialExecutor) ExecuteWithCredentials(_ context.Context, _ adapter.Operation, values []*credentialref.Value) (adapter.Effect, error) {
	implementation.retained = values[0].Bytes()
	panic(string(values[0].Bytes()))
}

func TestCredentialEffectClosesBytesOnInterruptedAdapterPanic(t *testing.T) {
	value, err := credentialref.NewValue([]byte("synthetic-private-canary"))
	if err != nil {
		t.Fatal(err)
	}
	implementation := &panickingCredentialExecutor{}
	effect, effectErr := invokeCredentialEffect(context.Background(), implementation, adapter.Operation{}, adapter.ExactExecutionBinding{}, []*credentialref.Value{value})
	if Code(effectErr) != generated.ErrorCodeRecoveryRequired || !effect.EffectObserved || strings.Contains(effectErr.Error(), "synthetic-private-canary") {
		t.Fatalf("adapter panic escaped or claimed no effect: effect=%#v err=%v", effect, effectErr)
	}
	for _, byteValue := range implementation.retained {
		if byteValue != 0 {
			t.Fatal("borrowed bytes survived interrupted effect")
		}
	}
}

func TestDefaultLiveSecretGateUnavailable(t *testing.T) {
	if Code((UnavailableGateVerifier{}).VerifySecretStep(context.Background(), generated.Plan{}, generated.PlanOperation{})) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatal("unregistered live gate verifier admitted a secret step")
	}
}

type boundRecordingExecutor struct {
	plainCalls int
	boundCalls int
	binding    adapter.ExactExecutionBinding
}

func (executor *boundRecordingExecutor) ExecuteWithCredentials(context.Context, adapter.Operation, []*credentialref.Value) (adapter.Effect, error) {
	executor.plainCalls++
	return adapter.Effect{Status: "succeeded", ResultDigest: digest("bound"), EffectObserved: true}, nil
}

func (executor *boundRecordingExecutor) ExecuteBoundWithCredentials(_ context.Context, _ adapter.Operation, binding adapter.ExactExecutionBinding, _ []*credentialref.Value) (adapter.Effect, error) {
	executor.boundCalls++
	executor.binding = binding
	return adapter.Effect{Status: "succeeded", ResultDigest: digest("bound"), EffectObserved: true}, nil
}

func TestInvokeCredentialEffectPrefersBoundExecutor(t *testing.T) {
	value, err := credentialref.NewValue([]byte("synthetic-private-canary"))
	if err != nil {
		t.Fatal(err)
	}
	executor := &boundRecordingExecutor{}
	binding := adapter.ExactExecutionBinding{PlanID: "plan-a", RunID: "run-a", StepID: "step-a", LeaseID: "lease-a", RecoveryEpoch: 2}
	if _, err := invokeCredentialEffect(context.Background(), executor, adapter.Operation{}, binding, []*credentialref.Value{value}); err != nil {
		t.Fatal(err)
	}
	if executor.boundCalls != 1 || executor.plainCalls != 0 || executor.binding.LeaseID != "lease-a" || executor.binding.RecoveryEpoch != 2 {
		t.Fatalf("bound executor not preferred: %#v", executor)
	}
	if value.Bytes() != nil {
		t.Fatal("borrowed credential value was not closed after the bound effect")
	}
}

// boundOnlyExecutor implements ONLY the bound credential boundary (like the local
// backup adapter): it must still be invoked, proving the engine no longer
// requires the plain CredentialExecutor interface.
type boundOnlyExecutor struct {
	boundCalls int
	binding    adapter.ExactExecutionBinding
}

func (executor *boundOnlyExecutor) ExecuteBoundWithCredentials(_ context.Context, _ adapter.Operation, binding adapter.ExactExecutionBinding, _ []*credentialref.Value) (adapter.Effect, error) {
	executor.boundCalls++
	executor.binding = binding
	return adapter.Effect{Status: "succeeded", ResultDigest: digest("boundonly"), EffectObserved: true}, nil
}

func TestInvokeCredentialEffectRunsBoundOnlyAdapter(t *testing.T) {
	value, err := credentialref.NewValue([]byte("synthetic-private-canary"))
	if err != nil {
		t.Fatal(err)
	}
	executor := &boundOnlyExecutor{}
	binding := adapter.ExactExecutionBinding{PlanID: "plan-a", RunID: "run-a", StepID: "step-a", LeaseID: "lease-a", RecoveryEpoch: 4}
	effect, err := invokeCredentialEffect(context.Background(), executor, adapter.Operation{}, binding, []*credentialref.Value{value})
	if err != nil || effect.Status != "succeeded" {
		t.Fatalf("bound-only adapter not executed: effect=%#v err=%v", effect, err)
	}
	if executor.boundCalls != 1 || executor.binding.RecoveryEpoch != 4 {
		t.Fatalf("bound-only executor state = %#v", executor)
	}
	if value.Bytes() != nil {
		t.Fatal("borrowed value not closed after bound-only effect")
	}
}
