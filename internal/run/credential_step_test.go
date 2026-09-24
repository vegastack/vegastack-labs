package run

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type fakeCredentialBindings struct {
	binding    credentialref.StepBinding
	bindings   []credentialref.StepBinding
	reference  generated.CredentialReference
	references map[string]generated.CredentialReference
	calls      int
}

func (source *fakeCredentialBindings) GetStepBindings(_ context.Context, _ generated.Plan, operationID string) ([]credentialref.StepBinding, error) {
	source.calls++
	if len(source.bindings) != 0 {
		selected := []credentialref.StepBinding{}
		for _, binding := range source.bindings {
			if binding.OperationID == operationID {
				selected = append(selected, binding)
			}
		}
		return selected, nil
	}
	if source.binding.OperationID == "" || source.binding.OperationID != operationID {
		return nil, nil
	}
	return []credentialref.StepBinding{source.binding}, nil
}
func (source *fakeCredentialBindings) GetReference(_ context.Context, referenceID string) (generated.CredentialReference, error) {
	if source.references != nil {
		return source.references[referenceID], nil
	}
	return source.reference, nil
}

type fakeCredentialProfiles struct{ scope store.GateAppliedProfile }

func (source fakeCredentialProfiles) GetAppliedProfileScope(context.Context) (store.GateAppliedProfile, error) {
	return source.scope, nil
}

type fakeCredentialRegistry struct {
	resolver   adapter.CredentialResolver
	calls      int
	capability string
}

func (registry *fakeCredentialRegistry) ResolveCredentialResolver(string, string, string) (adapter.CredentialResolver, error) {
	registry.calls++
	return registry.resolver, nil
}
func (registry *fakeCredentialRegistry) ResolveCredentialCapability(string, string, string) (string, error) {
	if registry.capability == "" {
		return "credential.native.read", nil
	}
	return registry.capability, nil
}

type countingCredentialResolver struct{ calls int }

func (resolver *countingCredentialResolver) Resolve(context.Context, credentialref.StepBinding) (*credentialref.Value, error) {
	resolver.calls++
	return credentialref.NewValue([]byte("synthetic-private-canary"))
}

type advancingCredentialResolver struct {
	advance  func()
	retained []byte
}

type rateLimitedCredentialResolver struct{}

func (rateLimitedCredentialResolver) Resolve(context.Context, credentialref.StepBinding) (*credentialref.Value, error) {
	return nil, failure.New(generated.ErrorCodeRateLimited, "provider-private-error-hidden", true)
}

func (resolver *advancingCredentialResolver) Resolve(context.Context, credentialref.StepBinding) (*credentialref.Value, error) {
	value, _ := credentialref.NewValue([]byte("synthetic-private-canary"))
	resolver.retained = value.Bytes()
	resolver.advance()
	return value, nil
}

type fakeCredentialPlanValidator struct{ calls int }

func (validator *fakeCredentialPlanValidator) ValidateCurrent(context.Context, generated.Plan) error {
	validator.calls++
	return nil
}

func TestCredentialStepRechecksAppliedReferenceAndExactLease(t *testing.T) {
	now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	plan := testPlan(now)
	plan.ExecutorMode, plan.AuthorizationBranch = "central", "human"
	plan.Binding.StateRevision = 3
	binding := credentialref.StepBinding{OperationID: plan.Operations[0].OperationID, AdapterID: plan.Operations[0].AdapterID, TargetID: plan.Operations[0].TargetID, ReferenceID: "ref-a", ConsumerID: plan.Operations[0].AdapterID, PurposeID: "deploy-a", MaterialVersion: "version-a", ResolverID: "native-a", StateRevision: 3, RecoveryEpoch: 0}
	plan.Operations[0].InputDigest = credentialref.OperationManifestDigest([]credentialref.StepBinding{binding}, binding.OperationID)
	plan.Extensions = []generated.ContractExtension{{Name: "x-credential-bindings", ValueDigest: credentialref.ManifestDigest([]credentialref.StepBinding{binding})}}
	activated := now.Format(time.RFC3339)
	reference := generated.CredentialReference{ReferenceID: binding.ReferenceID, ConsumerID: binding.ConsumerID, PurposeID: binding.PurposeID, TargetID: binding.TargetID, ResolverID: binding.ResolverID, MaterialVersion: binding.MaterialVersion, Fingerprint: digest("ciphertext"), Status: "active", StateRevision: 2, RecoveryEpoch: 0, ActivatedAt: &activated, VerifiedConsumerIDs: []string{binding.ConsumerID}}
	bindings := &fakeCredentialBindings{binding: binding, reference: reference}
	resolver := &countingCredentialResolver{}
	registry := &fakeCredentialRegistry{resolver: resolver}
	validator := &fakeCredentialPlanValidator{}
	profiles := &fakeCredentialProfiles{store.GateAppliedProfile{ProfileID: "profile-a", StateRevision: 2, RecoveryEpoch: 0, Capabilities: []string{"credential.native.read"}}}
	step := CredentialStep{Bindings: bindings, Resolvers: registry, Profiles: profiles, Plans: validator, Clock: func() time.Time { return now }}
	operation := plan.Operations[0]
	lease := generated.ExecutorLease{LeaseID: "lease-a", RunID: "run-a", StepID: "step-a", ExecutorID: operation.ExecutorID, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, OperationID: operation.OperationID, AdapterID: operation.AdapterID, TargetID: operation.TargetID, ArtifactDigest: operation.ArtifactDigest, RecoveryEpoch: 0, Status: "active", MaximumExpiresAt: now.Add(time.Minute).Format(time.RFC3339)}
	values, err := step.Resolve(context.Background(), plan, operation, lease)
	if err != nil || len(values) != 1 || resolver.calls != 1 || validator.calls != 3 {
		t.Fatalf("exact credential step: values=%d resolver=%d validator=%d err=%v", len(values), resolver.calls, validator.calls, err)
	}
	values[0].Close()
	profiles.scope.Capabilities = slices.Delete(profiles.scope.Capabilities, 0, 1)
	if _, err := step.Resolve(context.Background(), plan, operation, lease); Code(err) != generated.ErrorCodePrerequisiteBlocked || resolver.calls != 1 {
		t.Fatal("disabled applied capability reached resolver")
	}
	profiles.scope.Capabilities = []string{"credential.native.read"}
	profiles.scope.RecoveryEpoch = 1
	if _, err := step.Resolve(context.Background(), plan, operation, lease); Code(err) != generated.ErrorCodePrerequisiteBlocked || resolver.calls != 1 {
		t.Fatal("changed recovery epoch reached resolver")
	}
	profiles.scope.RecoveryEpoch = 0
	badLease := lease
	badLease.TargetID = "other-target"
	if _, err := step.Resolve(context.Background(), plan, operation, badLease); err == nil || resolver.calls != 1 {
		t.Fatal("wrong lease reached resolver")
	}
	bindings.reference.Status = "staged"
	if _, err := step.Resolve(context.Background(), plan, operation, lease); err == nil || resolver.calls != 1 {
		t.Fatal("staged reference reached resolver")
	}
	bindings.reference.Status = "active"
	currentTime := now
	step.Clock = func() time.Time { return currentTime }
	late := &advancingCredentialResolver{advance: func() { currentTime = now.Add(2 * time.Minute) }}
	registry.resolver = late
	if values, err := step.Resolve(context.Background(), plan, operation, lease); len(values) != 0 || Code(err) != generated.ErrorCodeInterrupted {
		t.Fatalf("expired lease after resolver returned values=%d err=%v", len(values), err)
	}
	for _, byteValue := range late.retained {
		if byteValue != 0 {
			t.Fatal("late resolver value not wiped")
		}
	}
	currentTime = now
	ctx, cancel := context.WithCancel(context.Background())
	late = &advancingCredentialResolver{advance: cancel}
	registry.resolver = late
	if values, err := step.Resolve(ctx, plan, operation, lease); len(values) != 0 || Code(err) != generated.ErrorCodeInterrupted {
		t.Fatalf("cancelled lease after resolver returned values=%d err=%v", len(values), err)
	}
	for _, byteValue := range late.retained {
		if byteValue != 0 {
			t.Fatal("cancelled resolver value not wiped")
		}
	}
	registry.resolver = rateLimitedCredentialResolver{}
	if _, err := step.Resolve(context.Background(), plan, operation, lease); Code(err) != generated.ErrorCodeRateLimited || strings.Contains(err.Error(), "provider-private-error-hidden") {
		t.Fatalf("rate limit lost or provider error leaked: %v", err)
	}
}

func TestScheduledCredentialStepKeepsSemanticInputAndRequiresScheduledAdmission(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	plan := testPlan(now)
	plan.ExecutorMode, plan.AuthorizationBranch, plan.Binding.StateRevision = "central", "preauthorized", 3
	binding := credentialref.StepBinding{OperationID: plan.Operations[0].OperationID, AdapterID: plan.Operations[0].AdapterID, TargetID: plan.Operations[0].TargetID, ReferenceID: "ref-a", ConsumerID: plan.Operations[0].AdapterID, PurposeID: "backup-encryption", MaterialVersion: "version-a", ResolverID: "native-a", StateRevision: 3, RecoveryEpoch: 0}
	plan.Operations[0].InputDigest = digest("semantic-backup-manifest")
	manifest := credentialref.ManifestDigest([]credentialref.StepBinding{binding})
	plan.Extensions = []generated.ContractExtension{{Name: "x-scheduled-credential-bindings", ValueDigest: manifest}, {Name: "x-scheduled-occurrence", ValueDigest: digest("occurrence")}, {Name: "x-scheduled-policy", ValueDigest: digest("policy")}}
	activated := now.Format(time.RFC3339)
	reference := generated.CredentialReference{ReferenceID: binding.ReferenceID, ConsumerID: binding.ConsumerID, PurposeID: binding.PurposeID, TargetID: binding.TargetID, ResolverID: binding.ResolverID, MaterialVersion: binding.MaterialVersion, Status: "active", StateRevision: 2, RecoveryEpoch: 0, ActivatedAt: &activated, VerifiedConsumerIDs: []string{binding.ConsumerID}}
	validator := &fakeCredentialPlanValidator{}
	step := CredentialStep{Bindings: &fakeCredentialBindings{binding: binding, reference: reference}, Resolvers: &fakeCredentialRegistry{resolver: &countingCredentialResolver{}}, Profiles: fakeCredentialProfiles{scope: store.GateAppliedProfile{ProfileID: "profile-a", StateRevision: 2, RecoveryEpoch: 0, Capabilities: []string{"credential.native.read"}}}, Plans: &fakeCredentialPlanValidator{}, ScheduledPlans: validator, Clock: func() time.Time { return now }}
	operation := plan.Operations[0]
	lease := generated.ExecutorLease{LeaseID: "lease-a", RunID: "run-a", StepID: "step-a", ExecutorID: operation.ExecutorID, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, OperationID: operation.OperationID, AdapterID: operation.AdapterID, TargetID: operation.TargetID, ArtifactDigest: operation.ArtifactDigest, RecoveryEpoch: 0, Status: "active", MaximumExpiresAt: now.Add(time.Minute).Format(time.RFC3339)}
	values, err := step.Resolve(context.Background(), plan, operation, lease)
	if err != nil || len(values) != 1 || validator.calls != 3 {
		t.Fatalf("scheduled resolve values=%d validation=%d err=%v", len(values), validator.calls, err)
	}
	values[0].Close()
	step.ScheduledPlans = nil
	if _, err := step.Resolve(context.Background(), plan, operation, lease); Code(err) != generated.ErrorCodePlanStale {
		t.Fatalf("missing scheduled admission err=%v", err)
	}
}

func TestCredentialStepClassifiesOnlyServerBoundOperationAsSecret(t *testing.T) {
	plan := testPlan(time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
	plan.Extensions = []generated.ContractExtension{{Name: "x-credential-bindings", ValueDigest: digest("synthetic-manifest")}}
	step := CredentialStep{Bindings: &fakeCredentialBindings{}, Plans: &fakeCredentialPlanValidator{}}
	if secret, err := step.IsSecretOperation(context.Background(), plan, plan.Operations[0]); err != nil || secret {
		t.Fatalf("server-verified unbound operation classified secret=%t err=%v", secret, err)
	}
}

type panickingSecondResolver struct {
	calls    int
	retained []byte
}

func (resolver *panickingSecondResolver) Resolve(context.Context, credentialref.StepBinding) (*credentialref.Value, error) {
	resolver.calls++
	if resolver.calls == 2 {
		panic("synthetic-private-canary")
	}
	value, _ := credentialref.NewValue([]byte("synthetic-private-canary"))
	resolver.retained = value.Bytes()
	return value, nil
}

func TestCredentialStepClosesEarlierValuesOnLaterResolverPanic(t *testing.T) {
	now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	plan := testPlan(now)
	plan.ExecutorMode, plan.AuthorizationBranch = "central", "human"
	plan.Binding.StateRevision = 3
	first := credentialref.StepBinding{OperationID: plan.Operations[0].OperationID, AdapterID: plan.Operations[0].AdapterID, TargetID: plan.Operations[0].TargetID, ReferenceID: "ref-a", ConsumerID: plan.Operations[0].AdapterID, PurposeID: "deploy-a", MaterialVersion: "version-a", ResolverID: "native-a", StateRevision: 3, RecoveryEpoch: 0}
	second := first
	second.ReferenceID, second.MaterialVersion = "ref-b", "version-b"
	all := []credentialref.StepBinding{first, second}
	plan.Operations[0].InputDigest = credentialref.OperationManifestDigest(all, first.OperationID)
	plan.Extensions = []generated.ContractExtension{{Name: "x-credential-bindings", ValueDigest: credentialref.ManifestDigest(all)}}
	activeAt := now.Format(time.RFC3339)
	makeReference := func(binding credentialref.StepBinding) generated.CredentialReference {
		return generated.CredentialReference{ReferenceID: binding.ReferenceID, ConsumerID: binding.ConsumerID, PurposeID: binding.PurposeID, TargetID: binding.TargetID, ResolverID: binding.ResolverID, MaterialVersion: binding.MaterialVersion, Status: "active", StateRevision: 2, RecoveryEpoch: 0, ActivatedAt: &activeAt, VerifiedConsumerIDs: []string{binding.ConsumerID}}
	}
	source := &fakeCredentialBindings{bindings: all, references: map[string]generated.CredentialReference{first.ReferenceID: makeReference(first), second.ReferenceID: makeReference(second)}}
	resolver := &panickingSecondResolver{}
	step := CredentialStep{Bindings: source, Resolvers: &fakeCredentialRegistry{resolver: resolver}, Profiles: fakeCredentialProfiles{scope: store.GateAppliedProfile{ProfileID: "profile-a", StateRevision: 2, RecoveryEpoch: 0, Capabilities: []string{"credential.native.read"}}}, Plans: &fakeCredentialPlanValidator{}, Clock: func() time.Time { return now }}
	operation := plan.Operations[0]
	lease := generated.ExecutorLease{LeaseID: "lease-a", RunID: "run-a", StepID: "step-a", ExecutorID: operation.ExecutorID, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, OperationID: operation.OperationID, AdapterID: operation.AdapterID, TargetID: operation.TargetID, ArtifactDigest: operation.ArtifactDigest, RecoveryEpoch: 0, Status: "active", MaximumExpiresAt: now.Add(time.Minute).Format(time.RFC3339)}
	values, err := step.Resolve(context.Background(), plan, operation, lease)
	if len(values) != 0 || Code(err) != generated.ErrorCodeRecoveryRequired || strings.Contains(err.Error(), "synthetic-private-canary") {
		t.Fatalf("resolver panic escaped or claimed ready: values=%d err=%v", len(values), err)
	}
	for _, byteValue := range resolver.retained {
		if byteValue != 0 {
			t.Fatal("first borrowed value survived later resolver panic")
		}
	}
}
