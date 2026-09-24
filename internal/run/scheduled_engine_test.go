package run

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type scheduledAdmissionProbe struct {
	calls, failAt int
}

func (probe *scheduledAdmissionProbe) ValidateScheduledPlan(context.Context, generated.Plan, time.Time) error {
	probe.calls++
	if probe.failAt == probe.calls {
		return runError(generated.ErrorCodePrerequisiteBlocked, "scheduled-prerequisite-changed")
	}
	return nil
}

type scheduledCoreProbe struct{ calls int }

func (probe *scheduledCoreProbe) Execute(_ context.Context, binding ExactStepBinding) (adapter.Effect, error) {
	probe.calls++
	return adapter.Effect{Status: "succeeded", ResultDigest: binding.Step.InputDigest, Changed: false, EffectObserved: true}, nil
}

type scheduledObservationPort struct{ calls int }

func (port *scheduledObservationPort) ObserveScheduled(_ context.Context, binding ExactStepBinding) (string, error) {
	port.calls++
	return binding.Step.InputDigest, nil
}
func (*scheduledCoreProbe) Verify(_ context.Context, _ ExactStepBinding, effect adapter.Effect) (adapter.Verification, error) {
	return adapter.Verification{Verified: true, Digest: effect.ResultDigest}, nil
}

func TestScheduledFiveActionKindsCrossBothEngineAdmissionBoundaries(t *testing.T) {
	cases := []struct {
		name, operation, adapterID string
		available                  bool
	}{
		{"gate-check", "schedule.gate.check", "core.schedule-observe", true},
		{"observation-refresh", "schedule.observation.refresh", "core.schedule-observe", true},
		{"backup-create", "backup.local.create", "local.backup", true},
		{"backup-integrity-verify", "backup.local.verify", "local.backup", true},
		{"audit-checkpoint-export", "audit.checkpoint.anchor", "core.audit", false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
			plan := testPlan(now)
			plan.AuthorizationBranch = "preauthorized"
			plan.Operations[0].OperationType = test.operation
			plan.Operations[0].AdapterID = test.adapterID
			plan.Operations[0].InputDigest = digest("scheduled-effect")
			plan.Operations[0].ArtifactDigest = plan.Operations[0].InputDigest
			plan.Extensions = []generated.ContractExtension{{Name: "x-scheduled-policy", ValueDigest: digest("policy")}, {Name: "x-scheduled-occurrence", ValueDigest: digest("occurrence")}}
			repository := newMemoryRepository(plan)
			registry := adapter.NewRegistry()
			implementation := &fakeAdapter{verify: true}
			if test.adapterID == "local.backup" {
				if err := registry.Register(test.adapterID, implementation); err != nil {
					t.Fatal(err)
				}
			}
			admission := &scheduledAdmissionProbe{}
			core := CoreEffect(&scheduledCoreProbe{})
			observation := &scheduledObservationPort{}
			if test.adapterID == "core.schedule-observe" {
				effect, err := NewScheduleObservationEffect(observation)
				if err != nil {
					t.Fatal(err)
				}
				core = CoreRouter{ScheduleObserve: effect}
			} else if test.adapterID == "core.audit" {
				// Production intentionally leaves Checkpoint nil until signer,
				// exporter, reader and encryptor dependencies are complete.
				core = CoreRouter{}
			}
			engine, err := NewEngine(Config{Repository: repository, Plans: repository, Admission: allowAdmission{}, Adapters: registry, Core: core, Scheduled: admission, Clock: func() time.Time { return now }, IDs: &deterministicIDs{}, LeaseContext: testLeaseContext})
			if err != nil {
				t.Fatal(err)
			}
			branch := "preauthorized"
			request := SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RecoveryEpoch: plan.Binding.RecoveryEpoch, IdempotencyKey: "scheduled-" + test.name, Extensions: []generated.ContractExtension{}}, Authorization: generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-" + test.name, PrincipalID: "policy-test", Action: "execute", TargetID: plan.Operations[0].TargetID, Allowed: true, Branch: &branch, ReasonCode: "allowed", GrantRevision: 1, RecoveryEpoch: plan.Binding.RecoveryEpoch, PlanDigest: plan.PlanDigest, DecidedAt: now.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}}
			completed, err := engine.Submit(context.Background(), request)
			if !test.available {
				if Code(err) != generated.ErrorCodePrerequisiteBlocked || completed.Status != "failed" || admission.calls != 2 {
					t.Fatalf("unavailable run=%#v admission-calls=%d err=%v", completed, admission.calls, err)
				}
				return
			}
			if err != nil || completed.Status != "succeeded" || admission.calls != 2 {
				t.Fatalf("run=%#v admission-calls=%d err=%v", completed, admission.calls, err)
			}
			if test.adapterID == "local.backup" && implementation.calls != 1 || test.adapterID == "core.schedule-observe" && observation.calls != 2 {
				t.Fatalf("adapter-calls=%d observation-calls=%d", implementation.calls, observation.calls)
			}
		})
	}
}

func TestScheduledEngineFailsClosedWithoutAdmissionOrAdapter(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	plan := testPlan(now)
	plan.AuthorizationBranch = "preauthorized"
	plan.Operations[0].OperationType = "backup.local.create"
	plan.Operations[0].AdapterID = "local.backup"
	plan.Extensions = []generated.ContractExtension{{Name: "x-scheduled-policy", ValueDigest: digest("policy")}, {Name: "x-scheduled-occurrence", ValueDigest: digest("occurrence")}}
	repository := newMemoryRepository(plan)
	engine, err := NewEngine(Config{Repository: repository, Plans: repository, Admission: allowAdmission{}, Adapters: adapter.NewRegistry(), Clock: func() time.Time { return now }, IDs: &deterministicIDs{}, LeaseContext: testLeaseContext})
	if err != nil {
		t.Fatal(err)
	}
	branch := "preauthorized"
	request := SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RecoveryEpoch: 0, IdempotencyKey: "scheduled-denied", Extensions: []generated.ContractExtension{}}, Authorization: generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-denied", PrincipalID: "policy-test", Action: "execute", TargetID: plan.Operations[0].TargetID, Allowed: true, Branch: &branch, ReasonCode: "allowed", GrantRevision: 1, RecoveryEpoch: 0, PlanDigest: plan.PlanDigest, DecidedAt: now.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}}
	if _, err := engine.Submit(context.Background(), request); Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("missing scheduled admission code=%q err=%v", Code(err), err)
	}

	repository = newMemoryRepository(plan)
	admission := &scheduledAdmissionProbe{}
	engine, err = NewEngine(Config{Repository: repository, Plans: repository, Admission: allowAdmission{}, Adapters: adapter.NewRegistry(), Scheduled: admission, Clock: func() time.Time { return now }, IDs: &deterministicIDs{}, LeaseContext: testLeaseContext})
	if err != nil {
		t.Fatal(err)
	}
	request.Reference.IdempotencyKey = "scheduled-missing-adapter"
	if failed, err := engine.Submit(context.Background(), request); adapter.Code(err) != generated.ErrorCodePrerequisiteBlocked || failed.Status != "failed" || admission.calls != 1 {
		t.Fatalf("missing adapter run=%#v calls=%d code=%q err=%v", failed, admission.calls, adapter.Code(err), err)
	}

	repository = newMemoryRepository(plan)
	implementation := &fakeAdapter{verify: true}
	registry := adapter.NewRegistry()
	if err := registry.Register("local.backup", implementation); err != nil {
		t.Fatal(err)
	}
	admission = &scheduledAdmissionProbe{failAt: 2}
	engine, err = NewEngine(Config{Repository: repository, Plans: repository, Admission: allowAdmission{}, Adapters: registry, Scheduled: admission, Clock: func() time.Time { return now }, IDs: &deterministicIDs{}, LeaseContext: testLeaseContext})
	if err != nil {
		t.Fatal(err)
	}
	request.Reference.IdempotencyKey = "scheduled-prerequisite-change"
	if failed, err := engine.Submit(context.Background(), request); Code(err) != generated.ErrorCodePrerequisiteBlocked || failed.Status != "failed" || admission.calls != 2 || implementation.calls != 0 {
		t.Fatalf("changed prerequisite run=%#v calls=%d effects=%d code=%q err=%v", failed, admission.calls, implementation.calls, Code(err), err)
	}
}

func TestScheduledAdmissionSelectsOccurrencesButNotPolicyActivation(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	admission := &scheduledAdmissionProbe{}
	engine := &Engine{scheduled: admission, clock: func() time.Time { return now }}
	plan := generated.Plan{AuthorizationBranch: "human", ExecutorMode: "central", Operations: []generated.PlanOperation{{AdapterID: "core.schedule", OperationType: "schedule.policy.activate"}}, Extensions: []generated.ContractExtension{{Name: "x-scheduled-policy", ValueDigest: digest("policy")}}}
	if err := engine.validateScheduled(context.Background(), plan); err != nil || admission.calls != 0 {
		t.Fatalf("policy activation entered occurrence admission: calls=%d err=%v", admission.calls, err)
	}
	plan.AuthorizationBranch = "preauthorized"
	if err := engine.validateScheduled(context.Background(), plan); Code(err) != generated.ErrorCodeAuthorizationDenied || admission.calls != 0 {
		t.Fatalf("preauthorized policy-only plan admitted: calls=%d err=%v", admission.calls, err)
	}
	plan.AuthorizationBranch = "human"
	plan.Extensions = append(plan.Extensions, generated.ContractExtension{Name: "x-scheduled-occurrence", ValueDigest: digest("occurrence")})
	if err := engine.validateScheduled(context.Background(), plan); err != nil || admission.calls != 1 {
		t.Fatalf("occurrence skipped scheduled admission: calls=%d err=%v", admission.calls, err)
	}
}
