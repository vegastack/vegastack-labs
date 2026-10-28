package server

import (
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func managedSelectionFixture() (adapter.ExactExecutionBinding, generated.Plan, generated.RunStep, store.CIManagedDeploymentAdmission) {
	selected, enrollment, _ := externalDeploymentFixture()
	executor := "executor-a"
	parent := adapter.ExactExecutionBinding{PlanID: "parent-ci", PlanDigest: hostaction.Digest("parent-ci"), StateRevision: 7, RecoveryEpoch: 2}
	step := generated.RunStep{OperationID: "external-deployment", OperationType: "application.deploy.production-like", AdapterID: "hosting.coolify.external", ExecutorID: executor, TargetID: selected.TargetID, ArtifactDigest: selected.ArtifactDigest, InputDigest: hostaction.Digest("input")}
	p := generated.Plan{PlanID: selected.PlanID, PlanDigest: selected.PlanDigest, ExecutorMode: "external", ExecutorID: &executor, Binding: generated.PlanBinding{StateRevision: 7, RecoveryEpoch: 2}, Extensions: []generated.ContractExtension{{Name: "x-ci-controller-plan", ValueDigest: parent.PlanDigest}}, Operations: []generated.PlanOperation{{OperationID: step.OperationID, OperationType: step.OperationType, AdapterID: step.AdapterID, ExecutorID: step.ExecutorID, TargetID: step.TargetID, ArtifactDigest: step.ArtifactDigest, InputDigest: step.InputDigest}}}
	proof := store.CIManagedDeploymentAdmission{ExecutionBinding: generated.CiJobExecutionBinding{BindingID: selected.ExecutionBindingID, AutomationPrincipalID: executor}, Enrollment: store.CIEnrollmentPolicy{Definition: generated.CiEnrollmentDefinition{EnrollmentID: enrollment.EnrollmentID, BindingDigest: hostaction.Digest(enrollment)}, Binding: enrollment}, ProviderRunID: "101", JobID: "202", RunnerID: "303", Attempt: 1, ObservationDigest: hostaction.Digest("consumed-observation")}
	return parent, p, step, proof
}
func TestManagedDeploymentSelectionUsesConsumedNumericAdmission(t *testing.T) {
	parent, p, step, proof := managedSelectionFixture()
	selected, principal, e := managedDeploymentSelection(parent, p, step, proof)
	if e != nil || selected.RunID != "101" || selected.JobID != "202" || selected.RunnerID != "303" || principal.Method != identity.ManagedCIControllerMethod || principal.Kind != identity.PrincipalPolicy {
		t.Fatal("consumed identity not selected", selected, principal, e)
	}
	for _, mode := range []string{"build", "wrong-principal", "wrong-target", "wrong-parent", "duplicate-parent", "wrong-epoch", "wrong-state", "noncanonical-job", "missing-runner", "bad-observation", "attempt"} {
		t.Run(mode, func(t *testing.T) {
			parent, p, step, proof := managedSelectionFixture()
			switch mode {
			case "build":
				proof.Enrollment.Binding.JobClass = "build"
				proof.Enrollment.Definition.BindingDigest = hostaction.Digest(proof.Enrollment.Binding)
			case "wrong-principal":
				proof.ExecutionBinding.AutomationPrincipalID = "build-executor"
			case "wrong-target":
				step.TargetID = "wrong-service"
			case "wrong-parent":
				parent.PlanDigest = hostaction.Digest("another-parent")
			case "duplicate-parent":
				p.Extensions = append(p.Extensions, p.Extensions[0])
			case "wrong-epoch":
				parent.RecoveryEpoch++
			case "wrong-state":
				parent.StateRevision++
			case "noncanonical-job":
				proof.JobID = "0202"
			case "missing-runner":
				proof.RunnerID = ""
			case "bad-observation":
				proof.ObservationDigest = "sha256:" + string(make([]byte, 64))
			case "attempt":
				proof.Attempt = 0
			}
			if _, _, e := managedDeploymentSelection(parent, p, step, proof); e == nil {
				t.Fatal("invalid consumed binding selected")
			}
		})
	}
}
