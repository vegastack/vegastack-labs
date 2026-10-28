package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/githubci"
	"github.com/vegastack/vegastack-labs/internal/ci"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"slices"
	"time"
)

type externalDeploymentAdmission struct {
	authority *store.Store
	registry  *adapter.Registry
	jobs      []generated.CiDeploymentJobBinding
	execution []generated.CiJobExecutionBinding
	observer  interface {
		Observe(context.Context, githubci.Target, *credentialref.Value) (ci.Observation, error)
	}
	managed interface {
		ManagedDeploymentAdmission(context.Context, adapter.ExactExecutionBinding, generated.Plan, generated.RunStep) (store.CIManagedDeploymentAdmission, error)
	}
	clock func() time.Time
}

func newExternalDeploymentAdmission(p serverconfig.Profile, s *store.Store, registry *adapter.Registry) (*externalDeploymentAdmission, error) {
	jobs, e := serverconfig.FreezeCIDeploymentJobs(p.CIDeploymentJobs, p.CIJobBindings, p.CIEnrollmentBindings)
	if e != nil {
		return nil, e
	}
	client, e := githubci.NewClient("https://api.github.com", nil)
	if e != nil {
		return nil, e
	}
	return &externalDeploymentAdmission{authority: s, registry: registry, jobs: jobs, execution: append([]generated.CiJobExecutionBinding(nil), p.CIJobBindings...), observer: client, clock: time.Now, managed: newCIJobRepository(s, store.NewGateRepository(s))}, nil
}
func deploymentJobMatches(b generated.CiDeploymentJobBinding, principal identity.Principal, p generated.Plan, step generated.RunStep) bool {
	if !identity.ValidPrincipal(principal) || identity.EffectivePrincipalKind(principal) != identity.PrincipalPolicy || p.ExecutorMode != "external" || p.ExecutorID == nil || *p.ExecutorID != principal.ID || b.ExecutorID != principal.ID || b.PlanID != p.PlanID || b.PlanDigest != p.PlanDigest || b.TargetID != step.TargetID || b.ArtifactDigest != step.ArtifactDigest || step.ExecutorID != principal.ID {
		return false
	}
	found := false
	for _, x := range p.Extensions {
		if x.Name == "x-executor-deployment-job" {
			if found || x.ValueDigest != serverconfig.CIDeploymentJobDigest(b) {
				return false
			}
			found = true
		}
	}
	return found
}
func (c *externalDeploymentAdmission) VerifyDeploymentJob(ctx context.Context, principal identity.Principal, p generated.Plan, step generated.RunStep) error {
	if c == nil || c.authority == nil || c.registry == nil || c.observer == nil || c.clock == nil {
		return actionFailure()
	}
	var selected generated.CiDeploymentJobBinding
	found := false
	for _, b := range c.jobs {
		if deploymentJobMatches(b, principal, p, step) {
			if found {
				return actionFailure()
			}
			selected = b
			found = true
		}
	}
	if !found {
		return actionFailure()
	}
	var execution generated.CiJobExecutionBinding
	for _, b := range c.execution {
		if b.BindingID == selected.ExecutionBindingID && b.AutomationPrincipalID == principal.ID && hostaction.Digest(b) == selected.ExecutionBindingDigest {
			execution = b
		}
	}
	return c.verifySelectedDeploymentJob(ctx, selected, execution, p, step, nil)
}

func (c *externalDeploymentAdmission) verifySelectedDeploymentJob(ctx context.Context, selected generated.CiDeploymentJobBinding, execution generated.CiJobExecutionBinding, p generated.Plan, step generated.RunStep, managedPolicy func() (store.CIEnrollmentPolicy, error)) error {
	if execution.ObserverReferenceID == "" {
		return actionFailure()
	}
	current := func() (store.CIEnrollmentPolicy, generated.CredentialReference, store.GateAppliedProfile, error) {
		var policy store.CIEnrollmentPolicy
		var e error
		if managedPolicy != nil {
			policy, e = managedPolicy()
		} else {
			policy, e = store.NewCIEnrollmentRepository(c.authority).ExecutionPolicy(ctx, selected.EnrollmentID, store.RevisionToken{StateRevision: p.Binding.StateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch})
		}
		if e != nil {
			return policy, generated.CredentialReference{}, store.GateAppliedProfile{}, e
		}
		if policy.Binding.JobClass != "deployment" || policy.Definition.BindingDigest != selected.EnrollmentDigest {
			return policy, generated.CredentialReference{}, store.GateAppliedProfile{}, actionFailure()
		}
		ref, e := store.NewCredentialRepository(c.authority).GetActiveVersion(ctx, execution.ObserverReferenceID, p.Binding.RecoveryEpoch)
		if e != nil {
			return policy, ref, store.GateAppliedProfile{}, e
		}
		scope, e := store.NewGateRepository(c.authority).GetAppliedProfileScope(ctx)
		if e != nil || scope.RecoveryEpoch != p.Binding.RecoveryEpoch || scope.StateRevision > p.Binding.StateRevision || !slices.Contains(scope.Capabilities, "credential.host-action.read") || ref.ActivatedAt == nil || ref.MaterialVersion != execution.ObserverMaterialVersion || ref.ConsumerID != hostaction.AdapterID || ref.PurposeID != store.CIJobObserverPurpose || ref.TargetID != execution.HostID || ref.StateRevision > p.Binding.StateRevision || !slices.Contains(ref.VerifiedConsumerIDs, hostaction.AdapterID) {
			return policy, ref, scope, actionFailure()
		}
		cap, e := c.registry.ResolveCredentialCapability(ref.ResolverID, hostaction.AdapterID, scope.ProfileID)
		if e != nil || cap != "credential.host-action.read" {
			return policy, ref, scope, actionFailure()
		}
		return policy, ref, scope, nil
	}
	policy, ref, scope, e := current()
	if e != nil {
		return e
	}
	resolver, e := c.registry.ResolveCredentialResolver(ref.ResolverID, hostaction.AdapterID, scope.ProfileID)
	if e != nil {
		return e
	}
	binding := credentialref.StepBinding{OperationID: step.OperationID, AdapterID: hostaction.AdapterID, ConsumerID: hostaction.AdapterID, PurposeID: store.CIJobObserverPurpose, TargetID: execution.HostID, ReferenceID: ref.ReferenceID, MaterialVersion: ref.MaterialVersion, ResolverID: ref.ResolverID, StateRevision: p.Binding.StateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch}
	value, e := resolver.Resolve(ctx, binding)
	if e != nil {
		if value != nil {
			value.Close()
		}
		return actionFailure()
	}
	if value == nil || len(value.Bytes()) == 0 {
		if value != nil {
			value.Close()
		}
		return actionFailure()
	}
	defer value.Close()
	again, after, afterScope, e := current()
	if e != nil || hostaction.Digest(again) != hostaction.Digest(policy) || hostaction.Digest(after) != hostaction.Digest(ref) || serviceProfileDigest(afterScope) != serviceProfileDigest(scope) {
		return actionFailure()
	}
	enrollment := deploymentEnrollment(policy.Binding, selected.RunnerID)
	observation, e := c.observer.Observe(ctx, githubci.Target{Enrollment: enrollment, RunID: selected.RunID, JobID: selected.JobID, Attempt: uint32(selected.Attempt)}, value)
	if e != nil {
		return actionFailure()
	}
	if e = matchDeploymentObservation(selected, policy.Binding, observation, c.clock()); e != nil {
		return e
	}
	again, after, afterScope, e = current()
	if e != nil || hostaction.Digest(again) != hostaction.Digest(policy) || hostaction.Digest(after) != hostaction.Digest(ref) || serviceProfileDigest(afterScope) != serviceProfileDigest(scope) {
		return actionFailure()
	}
	return nil
}

func deploymentEnrollment(b generated.CiEnrollmentBinding, runnerID string) ci.Enrollment {
	return ci.Enrollment{ID: b.EnrollmentID, Binding: ci.Binding{RepositoryID: b.RepositoryID, OwnerID: b.RepositoryOwnerID, Repository: b.Repository, WorkflowID: b.WorkflowID, WorkflowPath: b.WorkflowPath, WorkflowDigest: b.WorkflowDigest, Revision: b.Revision, Ref: b.Ref, Event: b.Event, JobName: b.JobName, RunnerID: runnerID, RunnerGroupID: b.RunnerGroupID, Labels: slices.Clone(b.Labels)}}
}
func matchDeploymentObservation(selected generated.CiDeploymentJobBinding, b generated.CiEnrollmentBinding, o ci.Observation, now time.Time) error {
	if b.JobClass != "deployment" || hostaction.Digest(b) != selected.EnrollmentDigest || o.RunID != selected.RunID || o.JobID != selected.JobID || o.Attempt != uint32(selected.Attempt) {
		return actionFailure()
	}
	if _, e := ci.Match(deploymentEnrollment(b, selected.RunnerID), o, now); e != nil {
		return actionFailure()
	}
	return nil
}
