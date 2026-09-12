package generated

import (
	"encoding/json"
	"os"
	"testing"
)

func phase4Fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../tooling/testdata/phase-4/contracts/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPhase4GeneratedValidationModesAndBindings(t *testing.T) {
	plan := phase4Fixture(t, "valid-plan.json")
	if err := ValidateContractJSON(SchemaIDPlan, plan, ContractExact); err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(plan, &value); err != nil {
		t.Fatal(err)
	}
	value["schemaVersion"] = "1.8.0"
	futureVersion, _ := json.Marshal(value)
	if err := ValidateContractJSON(SchemaIDPlan, futureVersion, ContractExact); err == nil {
		t.Fatal("exact validation accepted a future same-major version")
	}
	value["xFuture"] = "display-only"
	compatible, _ := json.Marshal(value)
	if err := ValidateContractJSON(SchemaIDPlan, compatible, ContractCompatibleRead); err != nil {
		t.Fatal(err)
	}
	value["xFuture"] = map[string]any{"nested": []any{map[string]any{"password": "private-canary"}}}
	unsafe, _ := json.Marshal(value)
	if err := ValidateContractJSON(SchemaIDPlan, unsafe, ContractCompatibleRead); err == nil {
		t.Fatal("compatible validation accepted a nested secret-shaped field")
	}
	openCarrier := map[string]any{
		"schema": "vegastack-labs.dev/run-result", "schemaVersion": "1.2.0", "toolVersion": "1.0.0", "command": "plan",
		"requestId": "request-synthetic-001", "runId": nil, "status": "succeeded", "changed": false, "recoveryEpoch": 4,
		"stateRevision": 11, "snapshotDigest": nil, "releaseBuildId": "build-synthetic-001", "sourceRevision": nil,
		"planId": nil, "errors": []any{}, "data": map[string]any{"nested": map[string]any{"privateKey": "private-canary"}},
	}
	openCarrierJSON, _ := json.Marshal(openCarrier)
	if err := ValidateContractJSON(SchemaIDRunResult, openCarrierJSON, ContractCompatibleRead); err == nil {
		t.Fatal("compatible validation accepted a secret-shaped field in an open carrier")
	}
	delete(value, "xFuture")
	delete(value, "binding")
	missingBinding, _ := json.Marshal(value)
	if err := ValidateContractJSON(SchemaIDPlan, missingBinding, ContractExact); err == nil {
		t.Fatal("exact validation accepted a missing plan binding")
	}

	var fixture struct {
		Lease   ExecutorLease    `json:"lease"`
		Receipt ExecutionReceipt `json:"receipt"`
	}
	if err := json.Unmarshal(phase4Fixture(t, "invalid-widened-receipt.json"), &fixture); err != nil {
		t.Fatal(err)
	}
	var typedPlan Plan
	if err := json.Unmarshal(plan, &typedPlan); err != nil {
		t.Fatal(err)
	}
	operation := typedPlan.Operations[0]
	step := RunStep{Sequence: operation.Sequence, OperationID: operation.OperationID, OperationType: operation.OperationType, AdapterID: operation.AdapterID, ExecutorID: operation.ExecutorID, TargetID: operation.TargetID, InputDigest: operation.InputDigest, ArtifactDigest: operation.ArtifactDigest, Idempotent: operation.Idempotent, StepID: fixture.Lease.StepID, Status: "running", EffectState: "intent-recorded"}
	run := Run{PlanID: typedPlan.PlanID, PlanDigest: typedPlan.PlanDigest, ExecutorID: operation.ExecutorID, RecoveryEpoch: typedPlan.Binding.RecoveryEpoch, Steps: []RunStep{step}}
	if err := ValidateExecutorLeaseBinding(typedPlan, run, fixture.Lease); err != nil {
		t.Fatal(err)
	}
	mutuallyWidenedLease := fixture.Lease
	mutuallyWidenedLease.TargetID = fixture.Receipt.TargetID
	if err := ValidateExecutorLeaseBinding(typedPlan, run, mutuallyWidenedLease); err == nil {
		t.Fatal("lease and receipt widened together beyond the plan")
	}
	if err := ValidateExecutionReceiptBinding(mutuallyWidenedLease, fixture.Receipt); err != nil {
		t.Fatal("test setup must keep widened lease and receipt mutually consistent")
	}
	if err := ValidateExecutionReceiptBinding(fixture.Lease, fixture.Receipt); err == nil {
		t.Fatal("widened receipt accepted")
	}
	if err := ValidateLeaseTiming(fixture.Lease); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRunTransition("queued", "running"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRunTransition("succeeded", "running"); err == nil {
		t.Fatal("terminal run restarted")
	}
}
