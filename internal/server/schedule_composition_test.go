//go:build linux

package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/schedule"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type scheduleCompositionAuthority struct {
	policy generated.ScheduledJobPolicy
	digest string
	calls  int
	failAt int
}

func (authority *scheduleCompositionAuthority) ValidateScheduledPlan(context.Context, generated.Plan, time.Time) error {
	authority.calls++
	if authority.failAt == authority.calls {
		return scheduleCompositionError{}
	}
	return nil
}
func (authority *scheduleCompositionAuthority) GetActivePolicyByDigest(_ context.Context, digest string) (generated.ScheduledJobPolicy, error) {
	if digest != authority.digest {
		return generated.ScheduledJobPolicy{}, scheduleCompositionError{}
	}
	return authority.policy, nil
}

type scheduleCompositionError struct{}

func (scheduleCompositionError) Error() string { return "scheduled authority changed" }

type scheduleCompositionDeclarations struct {
	declaration generated.DeclarationRevision
	calls       int
	failAt      int
}

func (source *scheduleCompositionDeclarations) GetRevision(context.Context, string, int64) (generated.DeclarationRevision, error) {
	source.calls++
	if source.calls == source.failAt {
		changed := source.declaration
		changed.Status = "draft"
		return changed, nil
	}
	return source.declaration, nil
}

type scheduleCompositionAuthorizer struct {
	policy generated.ScheduledJobPolicy
	calls  int
	failAt int
}

func (source *scheduleCompositionAuthorizer) AuthorizeScheduled(_ context.Context, _ string, plan generated.Plan) (generated.AuthorizationDecision, error) {
	source.calls++
	branch := "preauthorized"
	return generated.AuthorizationDecision{Allowed: source.calls != source.failAt, Branch: &branch, GrantRevision: source.policy.GrantRevision, RecoveryEpoch: source.policy.RecoveryEpoch, PlanDigest: plan.PlanDigest}, nil
}

type scheduleCompositionPrerequisites struct {
	clock  func() time.Time
	calls  int
	failAt int
}

func (source *scheduleCompositionPrerequisites) Current(_ context.Context, requirements []schedule.PrerequisiteRequirement) ([]schedule.PrerequisiteStatus, error) {
	source.calls++
	statuses := make([]schedule.PrerequisiteStatus, len(requirements))
	for index, requirement := range requirements {
		state := "current"
		if source.calls == source.failAt {
			state = "blocked"
		}
		statuses[index] = schedule.PrerequisiteStatus{Requirement: requirement, State: state, ObservedAt: source.clock(), RecoveryEpoch: requirement.RecoveryEpoch}
	}
	return statuses, nil
}

type scheduleCompositionPlans struct{ plan generated.Plan }

func (source scheduleCompositionPlans) Get(_ context.Context, planID string) (store.PlanCommitResult, error) {
	if planID != source.plan.PlanID {
		return store.PlanCommitResult{}, scheduleCompositionError{}
	}
	return store.PlanCommitResult{Plan: source.plan}, nil
}
func (scheduleCompositionPlans) ValidateCurrent(context.Context, generated.Plan) error { return nil }

type scheduleCompositionObserver struct{ calls int }

func (observer *scheduleCompositionObserver) ObserveScheduled(_ context.Context, binding runengine.ExactStepBinding) (string, error) {
	observer.calls++
	return binding.Step.InputDigest, nil
}

func runScheduledObservationComposition(t *testing.T, reject string) (generated.Run, error, int, int) {
	ctx := context.Background()
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	digest := func(character byte) string {
		value := make([]byte, 64)
		for index := range value {
			value[index] = character
		}
		return "sha256:" + string(value)
	}
	policy := generated.ScheduledJobPolicy{Schema: generated.SchemaIDScheduledJobPolicy, SchemaVersion: "1.1.0", PolicyID: "policy-observe", Revision: 1, DeclarationID: "declaration-observe", DeclarationRevision: 1, ActionKind: "observation-refresh", OperationType: "schedule.observation.refresh", AdapterID: "core.schedule-observe", ExactSourceIDs: []string{"source-a"}, ExactSubjectIDs: []string{"subject-a"}, ExactTargetIDs: []string{"target-a"}, MaximumWork: 1, CredentialReferenceIDs: []string{}, GrantRevision: 3, StateRevision: 1, RecoveryEpoch: 0, PolicyVersion: "1.0.0", RetentionRuleDigest: digest('a'), AnchorAt: now.Format(time.RFC3339), IntervalSeconds: 3600, WindowSeconds: 1800, CatchUp: "none", Concurrency: "forbid", MaxAttempts: 1, InitialBackoffSeconds: 1, MaximumBackoffSeconds: 1, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Enabled: true}
	_, policyDigest, err := schedule.CanonicalPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	action, _, err := (scheduledActionResolver{}).ResolveScheduledAction(ctx, policy, "job-observe")
	if err != nil {
		t.Fatal(err)
	}
	plan := generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", PlanID: "plan-observe", PlanDigest: digest('b'), DeclarationID: policy.DeclarationID, Binding: generated.PlanBinding{RecoveryEpoch: 0, PriorStateRevision: 1, StateRevision: 1, DeclarationRevision: 1, ObservationFingerprint: digest('c'), TargetDigest: digest('d'), ReasonDigest: digest('e'), PolicyVersion: "1.0.0", ToolVersion: "test", ContractVersion: "1.0.0"}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: "operation-observe", OperationType: action.OperationType, AdapterID: action.AdapterID, ExecutorID: "executor-central", TargetID: action.TargetIDs[0], InputDigest: action.InputDigest, ArtifactDigest: action.ArtifactDigest, Idempotent: true}}, Status: "planned", Risk: "routine", AuthorizationBranch: "preauthorized", ExecutorMode: "central", CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(20 * time.Minute).Format(time.RFC3339), ReadableDigest: digest('f'), Extensions: []generated.ContractExtension{{Name: "x-scheduled-policy", ValueDigest: policyDigest}, {Name: "x-scheduled-occurrence", ValueDigest: digest('1')}}}
	authority := &scheduleCompositionAuthority{policy: policy, digest: policyDigest}
	declarations := &scheduleCompositionDeclarations{declaration: generated.DeclarationRevision{DeclarationID: policy.DeclarationID, Revision: 1, Status: "committed", StateRevision: 1, RecoveryEpoch: 0}}
	authorizer := &scheduleCompositionAuthorizer{policy: policy}
	prerequisites := &scheduleCompositionPrerequisites{clock: func() time.Time { return now }}
	switch reject {
	case "durable schedule authority":
		authority.failAt = 2
	case "declaration currentness":
		declarations.failAt = 2
	case "effective grant":
		authorizer.failAt = 2
	case "prerequisite proof":
		prerequisites.failAt = 2
	}
	admission := scheduleAdmission{repository: authority, declarations: declarations, authorizer: authorizer, principalID: "runner-a", prerequisites: prerequisites}
	observer := &scheduleCompositionObserver{}
	effect, err := runengine.NewScheduleObservationEffect(observer)
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(ctx, store.Config{DatabasePath: filepath.Join(t.TempDir(), "control.db"), Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	engine, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(database), Plans: scheduleCompositionPlans{plan}, Admission: runengine.NewAdmissionGate(nil, func() time.Time { return now }), Adapters: adapter.NewRegistry(), Core: runengine.CoreRouter{ScheduleObserve: effect}, Scheduled: admission, Clock: func() time.Time { return now }, ExecutionContext: ctx})
	if err != nil {
		t.Fatal(err)
	}
	branch := "preauthorized"
	request := runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RecoveryEpoch: 0, IdempotencyKey: "schedule-observe", Extensions: []generated.ContractExtension{}}, Authorization: generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-observe", PrincipalID: "runner-a", Action: "execute", TargetID: "target-a", Allowed: true, Branch: &branch, ReasonCode: "allowed", GrantRevision: 3, RecoveryEpoch: 0, PlanDigest: plan.PlanDigest, DecidedAt: now.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}, Attribution: audit.Attribution{AuthenticatedPrincipalID: "runner-a", AuthenticatedPrincipalMethod: "local-os-peer"}}
	completed, err := engine.Submit(ctx, request)
	return completed, err, authority.calls, observer.calls
}

func TestScheduledObservationUsesProductionAdmissionAndEngine(t *testing.T) {
	completed, err, admissions, observations := runScheduledObservationComposition(t, "")
	if err != nil || completed.Status != "succeeded" || admissions != 2 || observations != 2 {
		t.Fatalf("run=%#v admission=%d observation=%d err=%v", completed, admissions, observations, err)
	}
}

func TestScheduledObservationRejectsPostPlanAuthorityChanges(t *testing.T) {
	for _, rejection := range []string{"durable schedule authority", "declaration currentness", "effective grant", "prerequisite proof"} {
		t.Run(rejection, func(t *testing.T) {
			completed, err, admissions, observations := runScheduledObservationComposition(t, rejection)
			if err != nil || completed.Status != "failed" || admissions != 2 || observations != 0 {
				t.Fatalf("run=%#v admission=%d observation=%d err=%v", completed, admissions, observations, err)
			}
		})
	}
}

func TestScheduledBackupLiveGateRechecksCurrentPrerequisiteProof(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	policy := generated.ScheduledJobPolicy{
		Schema: generated.SchemaIDScheduledJobPolicy, SchemaVersion: "1.1.0", PolicyID: "policy-backup", Revision: 1,
		DeclarationID: "declaration-backup", DeclarationRevision: 1, ActionKind: "backup-create", OperationType: "backup.local.create", AdapterID: "local.backup",
		ExactSourceIDs: []string{"backup-policy-a", "source-a"}, ExactSubjectIDs: []string{"owner-a"}, ExactTargetIDs: []string{"target-a"}, MaximumWork: 1,
		CredentialReferenceIDs: []string{"credential-a"}, GrantRevision: 3, StateRevision: 1, RecoveryEpoch: 0, PolicyVersion: "1.0.0", RetentionRuleDigest: digest,
		AnchorAt: now.Format(time.RFC3339), IntervalSeconds: 3600, WindowSeconds: 1800, CatchUp: "none", Concurrency: "forbid", MaxAttempts: 1,
		InitialBackoffSeconds: 1, MaximumBackoffSeconds: 1, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Enabled: true,
	}
	_, policyDigest, err := schedule.CanonicalPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	plan := generated.Plan{
		PlanID: "plan-backup", PlanDigest: digest, DeclarationID: policy.DeclarationID,
		Binding:             generated.PlanBinding{StateRevision: 1, DeclarationRevision: 1, RecoveryEpoch: 0},
		AuthorizationBranch: "preauthorized", ExecutorMode: "central",
		Extensions: []generated.ContractExtension{{Name: "x-scheduled-policy", ValueDigest: policyDigest}, {Name: "x-scheduled-occurrence", ValueDigest: digest}, {Name: "x-scheduled-credential-bindings", ValueDigest: digest}, {Name: "x-backup-policy", ValueDigest: digest}},
	}
	operation := generated.PlanOperation{AdapterID: "local.backup", OperationType: "backup.local.create"}
	authority := &scheduleCompositionAuthority{policy: policy, digest: policyDigest}
	declarations := &scheduleCompositionDeclarations{declaration: generated.DeclarationRevision{DeclarationID: policy.DeclarationID, Revision: 1, Status: "committed", StateRevision: 1, RecoveryEpoch: 0}}
	authorizer := &scheduleCompositionAuthorizer{policy: policy}
	prerequisites := &scheduleCompositionPrerequisites{clock: func() time.Time { return now }, failAt: 2}
	gate := scheduledBackupLiveGate{admission: scheduleAdmission{repository: authority, declarations: declarations, authorizer: authorizer, principalID: "runner-a", prerequisites: prerequisites}, clock: func() time.Time { return now }}
	if err := gate.VerifySecretStep(context.Background(), plan, operation); err != nil {
		t.Fatalf("current proof rejected: %v", err)
	}
	if err := gate.VerifySecretStep(context.Background(), plan, operation); err == nil {
		t.Fatal("changed backup prerequisite proof accepted")
	}
}
