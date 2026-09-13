package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

type phase4ControlOperations struct {
	*stubControlOperations
	planResponse  localapi.TypedResponse[generated.Plan]
	runResponse   localapi.TypedResponse[generated.Run]
	config        string
	declarationID string
	revision      int64
	planID        string
	runID         string
	phase4Command string
}

func (stub *phase4ControlOperations) Plan(_ context.Context, config, declarationID string, revision int64) (localapi.TypedResponse[generated.Plan], error) {
	stub.config, stub.declarationID, stub.revision, stub.phase4Command = config, declarationID, revision, generated.CommandNamePlan
	return stub.planResponse, nil
}

func (stub *phase4ControlOperations) Apply(_ context.Context, config, planID string) (localapi.TypedResponse[generated.Run], error) {
	stub.config, stub.planID, stub.phase4Command = config, planID, generated.CommandNameApply
	return stub.runResponse, nil
}

func (stub *phase4ControlOperations) InspectRun(_ context.Context, config, runID string) (localapi.TypedResponse[generated.Run], error) {
	stub.config, stub.runID, stub.phase4Command = config, runID, generated.CommandNameRunInspect
	return stub.runResponse, nil
}

func (stub *phase4ControlOperations) CancelRun(_ context.Context, config, runID string) (localapi.TypedResponse[generated.Run], error) {
	stub.config, stub.runID, stub.phase4Command = config, runID, generated.CommandNameRunCancel
	return stub.runResponse, nil
}

func (stub *phase4ControlOperations) ResumeRun(_ context.Context, config, runID string) (localapi.TypedResponse[generated.Run], error) {
	stub.config, stub.runID, stub.phase4Command = config, runID, generated.CommandNameRunResume
	return stub.runResponse, nil
}

func TestPlanHumanAndJSONRenderSameDigestAndTargets(t *testing.T) {
	plan := phase4TestPlan()
	operations := phase4Operations(t, plan, phase4TestRun(plan, generated.RunStatusSucceeded))
	humanCode, human, humanErr := runTestAppWithOptions(t, context.Background(), []string{"plan", "--config", "profile.json", "--declaration-id", plan.DeclarationID, "--revision", "2"}, nil, WithControlOperations(operations, nil))
	if humanCode != 0 || humanErr != "" || operations.declarationID != plan.DeclarationID || operations.revision != 2 || operations.config != "profile.json" {
		t.Fatalf("human plan = %d %q %q operation=%#v", humanCode, human, humanErr, operations)
	}
	for _, fact := range []string{plan.PlanID, plan.PlanDigest, plan.Operations[0].TargetID, plan.Operations[1].TargetID, plan.Risk, plan.AuthorizationBranch, plan.ExpiresAt} {
		if !strings.Contains(human, fact) {
			t.Fatalf("human plan omitted %q: %s", fact, human)
		}
	}
	if !strings.Contains(human, "explicit human acknowledgement required") {
		t.Fatalf("human plan omitted approval requirement: %s", human)
	}

	operations = phase4Operations(t, plan, phase4TestRun(plan, generated.RunStatusSucceeded))
	jsonCode, machine, machineErr := runTestAppWithOptions(t, context.Background(), []string{"plan", "--config", "profile.json", "--declaration-id", plan.DeclarationID, "--revision", "2", "--output", "json"}, nil, WithControlOperations(operations, nil))
	if jsonCode != 0 || machineErr != "" || machine != string(operations.planResponse.Raw) {
		t.Fatalf("machine plan = %d %q %q", jsonCode, machine, machineErr)
	}
	var envelope generated.RunResult
	var decoded generated.Plan
	if json.Unmarshal([]byte(machine), &envelope) != nil || json.Unmarshal(envelope.Data, &decoded) != nil || decoded.PlanDigest != plan.PlanDigest || len(decoded.Operations) != 2 || decoded.Operations[0].TargetID != plan.Operations[0].TargetID || decoded.Operations[1].TargetID != plan.Operations[1].TargetID {
		t.Fatalf("machine plan lost parity: %s", machine)
	}
}

func TestApplyAndRunCommandsRenderOnlyServerOwnedState(t *testing.T) {
	plan := phase4TestPlan()
	run := phase4TestRun(plan, generated.RunStatusPartial)
	tests := []struct {
		command string
		args    []string
	}{
		{generated.CommandNameApply, []string{"apply", "--config", "profile.json", "--plan-id", plan.PlanID}},
		{generated.CommandNameRunInspect, []string{"run", "inspect", "--config", "profile.json", "--run-id", run.RunID}},
		{generated.CommandNameRunCancel, []string{"run", "cancel", "--config", "profile.json", "--run-id", run.RunID}},
		{generated.CommandNameRunResume, []string{"run", "resume", "--config", "profile.json", "--run-id", run.RunID}},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			operations := phase4Operations(t, plan, run)
			code, stdout, stderr := runTestAppWithOptions(t, context.Background(), test.args, nil, WithControlOperations(operations, nil))
			if code != 0 || stderr != "" || operations.phase4Command != test.command {
				t.Fatalf("run command = %d %q %q called=%q", code, stdout, stderr, operations.phase4Command)
			}
			for _, fact := range []string{run.RunID, run.PlanDigest, run.Status, run.VerificationStatus, run.RollbackStatus, "1", "recovery required"} {
				if !strings.Contains(strings.ToLower(stdout), strings.ToLower(fact)) {
					t.Fatalf("run output omitted %q: %s", fact, stdout)
				}
			}
		})
	}
}

func phase4Operations(t *testing.T, plan generated.Plan, run generated.Run) *phase4ControlOperations {
	t.Helper()
	return &phase4ControlOperations{
		stubControlOperations: successfulControlOperations(t),
		planResponse:          operationResponse(t, "api.v1.plans.create", true, plan.Binding.RecoveryEpoch, plan.Binding.StateRevision, plan),
		runResponse:           operationResponse(t, "api.v1.runs.get", run.Changed, run.RecoveryEpoch, run.StateRevision, run),
	}
}

func phase4TestPlan() generated.Plan {
	digest := "sha256:" + strings.Repeat("1", 64)
	return generated.Plan{
		Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", PlanID: "plan-phase4", PlanDigest: digest, DeclarationID: "change-phase4",
		Binding: generated.PlanBinding{RecoveryEpoch: 3, PriorStateRevision: 6, StateRevision: 7, DeclarationRevision: 2, ObservationFingerprint: "sha256:" + strings.Repeat("2", 64), TargetDigest: "sha256:" + strings.Repeat("3", 64), ReasonDigest: "sha256:" + strings.Repeat("4", 64), PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0"},
		Operations: []generated.PlanOperation{
			{Sequence: 1, OperationID: "operation-one", OperationType: "configuration.update", AdapterID: "adapter-fixture", ExecutorID: "executor-central", TargetID: "target-one", InputDigest: digest, ArtifactDigest: digest, Idempotent: true},
			{Sequence: 2, OperationID: "operation-two", OperationType: "configuration.update", AdapterID: "adapter-fixture", ExecutorID: "executor-central", TargetID: "target-two", InputDigest: digest, ArtifactDigest: digest, Idempotent: true},
		},
		Status: "planned", Risk: "routine", AuthorizationBranch: "human", ExecutorMode: "central", CreatedAt: "2026-09-13T06:00:00Z", ExpiresAt: "2026-09-13T06:30:00Z", ReadableDigest: digest, Extensions: []generated.ContractExtension{},
	}
}

func phase4TestRun(plan generated.Plan, status string) generated.Run {
	ack := "ack-phase4"
	return generated.Run{
		Schema: generated.SchemaIDRun, SchemaVersion: "1.0.0", RunID: "run-phase4", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest,
		AuthorizationDecisionID: "decision-phase4", AcknowledgementID: &ack, PolicyVersion: plan.Binding.PolicyVersion, ExecutorMode: "central", ExecutorID: "executor-central", ExecutorBindingDigest: "sha256:" + strings.Repeat("5", 64),
		Status: status, Steps: []generated.RunStep{
			{Sequence: 1, OperationID: "operation-one", OperationType: "configuration.update", AdapterID: "adapter-fixture", ExecutorID: "executor-central", TargetID: "target-one", InputDigest: plan.Operations[0].InputDigest, ArtifactDigest: plan.Operations[0].ArtifactDigest, Idempotent: true, StepID: "step-one", Status: "succeeded", EffectState: "verified"},
			{Sequence: 2, OperationID: "operation-two", OperationType: "configuration.update", AdapterID: "adapter-fixture", ExecutorID: "executor-central", TargetID: "target-two", InputDigest: plan.Operations[1].InputDigest, ArtifactDigest: plan.Operations[1].ArtifactDigest, Idempotent: true, StepID: "step-two", Status: "partial", EffectState: "effect-unknown"},
		},
		RollbackStatus: "required", VerificationStatus: "incomplete", Changed: true, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch,
		CreatedAt: "2026-09-13T06:00:00Z", UpdatedAt: "2026-09-13T06:01:00Z", Extensions: []generated.ContractExtension{},
	}
}
