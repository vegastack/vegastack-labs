package server

import (
	"context"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// managedDeploymentSelection never accepts numeric provider identity from a
// job, claim request or static configuration. The repository supplies the
// consumed admission, after rechecking both current execution boundaries.
func managedDeploymentSelection(parent adapter.ExactExecutionBinding, p generated.Plan, step generated.RunStep, proof store.CIManagedDeploymentAdmission) (generated.CiDeploymentJobBinding, identity.Principal, error) {
	empty := generated.CiDeploymentJobBinding{}
	deny := func() (generated.CiDeploymentJobBinding, identity.Principal, error) {
		return empty, identity.Principal{}, actionFailure()
	}
	execution, enrollment := proof.ExecutionBinding, proof.Enrollment
	if p.ExecutorMode != "external" || p.ExecutorID == nil || *p.ExecutorID != execution.AutomationPrincipalID || step.ExecutorID != *p.ExecutorID || p.PlanID == parent.PlanID || p.Binding.StateRevision != parent.StateRevision || p.Binding.RecoveryEpoch != parent.RecoveryEpoch || len(p.Operations) != 1 || enrollment.Binding.JobClass != "deployment" || enrollment.Definition.BindingDigest != hostaction.Digest(enrollment.Binding) || proof.Attempt < 1 || proof.Attempt > int64(^uint32(0)) {
		return deny()
	}
	op := p.Operations[0]
	if op.OperationID != step.OperationID || op.OperationType != step.OperationType || op.AdapterID != step.AdapterID || op.ExecutorID != step.ExecutorID || op.TargetID != step.TargetID || op.InputDigest != step.InputDigest || op.ArtifactDigest != step.ArtifactDigest {
		return deny()
	}
	count := 0
	for _, extension := range p.Extensions {
		if extension.Name == "x-ci-controller-plan" {
			count++
			if extension.ValueDigest != parent.PlanDigest {
				return deny()
			}
		}
	}
	if count != 1 || !strings.HasPrefix(proof.ObservationDigest, "sha256:") || len(proof.ObservationDigest) != 71 {
		return deny()
	}
	if _, e := hex.DecodeString(proof.ObservationDigest[7:]); e != nil {
		return deny()
	}
	for _, id := range []string{proof.ProviderRunID, proof.JobID, proof.RunnerID} {
		n, e := strconv.ParseInt(id, 10, 64)
		if e != nil || n <= 0 || strconv.FormatInt(n, 10) != id {
			return deny()
		}
	}
	principal := identity.Principal{ID: execution.AutomationPrincipalID, Kind: identity.PrincipalPolicy, Method: identity.ManagedCIControllerMethod}
	if !identity.ValidPrincipal(principal) {
		return deny()
	}
	selected := generated.CiDeploymentJobBinding{Schema: generated.SchemaIDCiDeploymentJobBinding, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, ExecutionBindingID: execution.BindingID, ExecutionBindingDigest: hostaction.Digest(execution), EnrollmentID: enrollment.Definition.EnrollmentID, EnrollmentDigest: hostaction.Digest(enrollment.Binding), ExecutorID: principal.ID, TargetID: step.TargetID, ArtifactDigest: step.ArtifactDigest, RunID: proof.ProviderRunID, JobID: proof.JobID, RunnerID: proof.RunnerID, Attempt: proof.Attempt}
	return selected, principal, nil
}

// VerifyManagedDeploymentJob is used only by the in-process managed executor
// wrappers. Static enrolled external jobs continue through VerifyDeploymentJob.
func (c *externalDeploymentAdmission) VerifyManagedDeploymentJob(ctx context.Context, parent adapter.ExactExecutionBinding, p generated.Plan, step generated.RunStep) (identity.Principal, error) {
	if c == nil || c.authority == nil || c.registry == nil || c.observer == nil || c.clock == nil || c.managed == nil {
		return identity.Principal{}, actionFailure()
	}
	proof, e := c.managed.ManagedDeploymentAdmission(ctx, parent, p, step)
	if e != nil {
		return identity.Principal{}, e
	}
	selected, principal, e := managedDeploymentSelection(parent, p, step, proof)
	if e != nil {
		return identity.Principal{}, e
	}
	policy := func() (store.CIEnrollmentPolicy, error) {
		actual, e := c.managed.ManagedDeploymentAdmission(ctx, parent, p, step)
		if e != nil {
			return store.CIEnrollmentPolicy{}, e
		}
		if hostaction.Digest(actual) != hostaction.Digest(proof) {
			return store.CIEnrollmentPolicy{}, actionFailure()
		}
		return actual.Enrollment, nil
	}
	if e := c.verifySelectedDeploymentJob(ctx, selected, proof.ExecutionBinding, p, step, policy); e != nil {
		return identity.Principal{}, e
	}
	return principal, nil
}
