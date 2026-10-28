package plan

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
	"sort"
	"strings"
)

type ciDeploymentCompanions interface {
	ExternalDeploymentPolicy(string) (store.CIExternalDeploymentPolicy, error)
	CommitCICompanion(context.Context, store.CICompanionCommit) (store.PlanCommitResult, error)
}

func (s *Service) ensureCICompanion(ctx context.Context, parent store.PlanCommitResult, author AuthorScope) (store.PlanCommitResult, error) {
	if parent.Plan.CIJob == nil || parent.Plan.CIJob.DeploymentDigest == "" {
		return parent, nil
	}
	repo, ok := s.config.Repository.(ciDeploymentCompanions)
	if !ok {
		return store.PlanCommitResult{}, planError(generated.ErrorCodePrerequisiteBlocked)
	}
	policy, e := repo.ExternalDeploymentPolicy(parent.Plan.CIJob.ExecutionBindingID)
	if e != nil {
		return store.PlanCommitResult{}, e
	}
	if policy.Binding.BindingID == "" || policy.Digest() != parent.Plan.CIJob.DeploymentDigest {
		return store.PlanCommitResult{}, planError(generated.ErrorCodePlanStale)
	}
	p := parent.Plan
	p.PlanID = ""
	p.PlanDigest = ""
	p.CIJob = nil
	p.ExecutorMode = "external"
	p.ExecutorID = &policy.Binding.ExecutorID
	p.Risk = "production-like"
	p.AuthorizationBranch = "human"
	b := policy.Credential(p.Binding.StateRevision, p.Binding.RecoveryEpoch)
	p.Operations = []generated.PlanOperation{{Sequence: 1, OperationID: store.CIExternalDeploymentOperationID, OperationType: store.CIExternalDeploymentOperation, AdapterID: store.CIExternalDeploymentAdapter, ExecutorID: policy.Binding.ExecutorID, TargetID: policy.Definition.ServiceID, ArtifactDigest: policy.Artifact.Digest, InputDigest: credentialref.OperationManifestDigest([]credentialref.StepBinding{b}, store.CIExternalDeploymentOperationID)}}
	p.Binding.TargetDigest = hostaction.Digest([]string{policy.Definition.ServiceID})
	p.Extensions = append([]generated.ContractExtension(nil), p.Extensions...)
	p.Extensions = append(p.Extensions, generated.ContractExtension{Name: "x-ci-controller-plan", ValueDigest: parent.Plan.PlanDigest}, generated.ContractExtension{Name: "x-external-deployment", ValueDigest: policy.Digest()}, generated.ContractExtension{Name: "x-external-deployment-credentials", ValueDigest: credentialref.ManifestDigest([]credentialref.StepBinding{b})})
	sort.Slice(p.Extensions, func(i, j int) bool { return p.Extensions[i].Name < p.Extensions[j].Name })
	readable := readablePlan(p)
	p.ReadableDigest = sha([]byte(readable))
	p.PlanDigest, e = planDigest(p)
	if e != nil {
		return store.PlanCommitResult{}, e
	}
	p.PlanID = "plan-" + strings.TrimPrefix(p.PlanDigest, "sha256:")[:32]
	attr := audit.Attribution{AuthenticatedPrincipalID: author.PrincipalID, AuthenticatedPrincipalMethod: author.PrincipalMethod}
	if author.AgentName != "" {
		attr.Agent = &audit.AgentMetadata{Name: author.AgentName, SessionID: author.AgentSessionID}
	}
	companion, e := repo.CommitCICompanion(ctx, store.CICompanionCommit{ParentPlanID: parent.Plan.PlanID, Plan: p, Readable: readable, Attribution: attr})
	if e != nil {
		return store.PlanCommitResult{}, e
	}
	parent.CompanionPlanID = companion.Plan.PlanID
	parent.CompanionPlanDigest = companion.Plan.PlanDigest
	return parent, nil
}

// ValidateManagedDeploymentPlan enables only inert reservation of the exact
// protected companion. Actual execution still requires managed job admission.
func (s *Service) ValidateManagedDeploymentPlan(ctx context.Context, p generated.Plan) error {
	if e := s.ValidateCurrent(ctx, p); e != nil {
		return e
	}
	repo, ok := s.config.Repository.(interface {
		ValidateManagedDeploymentPlan(context.Context, generated.Plan) error
	})
	if !ok {
		return planError(generated.ErrorCodeAuthorizationDenied)
	}
	return repo.ValidateManagedDeploymentPlan(ctx, p)
}
