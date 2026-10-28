package store

import (
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

const CIExternalDeploymentAdapter = "hosting.coolify.external"
const CIExternalDeploymentOperation = "application.deploy.production-like"
const CIExternalDeploymentOperationID = "external-deployment"

// CIExternalDeploymentPolicy is the provider-neutral, secret-free result of
// freezing one protected deployment profile and its verified immutable artifact.
type CIExternalDeploymentPolicy struct {
	Binding             generated.CiExternalDeploymentBinding
	Definition          generated.ServiceDefinition
	Artifact            generated.ServiceDeploymentArtifact
	ConfigurationDigest string
	ReferenceID         string
	ResolverID          string
}

func (p CIExternalDeploymentPolicy) Digest() string { return hostaction.Digest(p) }
func (p CIExternalDeploymentPolicy) Credential(state, epoch int64) credentialref.StepBinding {
	return credentialref.StepBinding{OperationID: CIExternalDeploymentOperationID, AdapterID: CIExternalDeploymentAdapter, TargetID: p.Definition.ServiceID, ReferenceID: p.ReferenceID, ConsumerID: "hosting.coolify.deploy", PurposeID: "hosting-deploy", MaterialVersion: p.Binding.MaterialVersion, ResolverID: p.ResolverID, StateRevision: state, RecoveryEpoch: epoch}
}
func (r *CIJobRepository) ExternalDeploymentPolicy(executionBinding string) (CIExternalDeploymentPolicy, error) {
	if r == nil || r.store == nil {
		return CIExternalDeploymentPolicy{}, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	var found *CIExternalDeploymentPolicy
	for _, p := range r.store.config.CIExternalDeploymentPolicies {
		if p.Binding.ExecutionBindingID == executionBinding {
			if found != nil {
				return CIExternalDeploymentPolicy{}, actionError(generated.ErrorCodeIntegrityFailure)
			}
			copy := p
			found = &copy
		}
	}
	if found == nil {
		return CIExternalDeploymentPolicy{}, nil
	}
	return *found, nil
}
func (r *CIJobRepository) validateExternalDeployment(actor identity.Principal, row discoveryRow, in generated.CiJobRequest) error {
	p, e := r.ExternalDeploymentPolicy(in.ExecutionBindingID)
	if e != nil {
		return e
	}
	if p.Binding.BindingID == "" {
		if in.DeploymentDigest != "" {
			return actionError(generated.ErrorCodePlanStale)
		}
		return nil
	}
	if in.DeploymentDigest != p.Digest() || p.Binding.ExecutorID == "" || p.Binding.ServiceID != p.Definition.ServiceID || p.Artifact.ArtifactID != p.Binding.ArtifactID {
		return actionError(generated.ErrorCodePlanStale)
	}
	record, e := readService(row, p.Definition.ServiceID)
	if e != nil || record.Definition != p.Definition {
		return actionError(generated.ErrorCodePlanStale)
	}
	if e = NewServiceRepository(r.store).authorize(actor, row, p.Definition, "read", "service.read"); e != nil {
		return e
	}
	return NewServiceRepository(r.store).authorize(actor, row, p.Definition, "author", "service.deploy.prepare")
}

// A managed policy identity consumes an independently approved human plan; it
// never authorizes that plan. The generic policy evaluator intentionally denies
// policy identities the human approval branch, so this narrow executor check
// validates only the current, exact delivery grant after human acknowledgement.
func authorizeCIManagedExecutor(row discoveryRow, p generated.Plan, executorID, targetID string) error {
	if p.ExecutorMode != "external" || p.AuthorizationBranch != "human" || p.ExecutorID == nil || *p.ExecutorID != executorID || len(p.Operations) != 1 || p.Operations[0].OperationType != CIExternalDeploymentOperation || p.Operations[0].AdapterID != CIExternalDeploymentAdapter || p.Operations[0].TargetID != targetID {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	var count int
	if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.principal_kind='policy' AND p.status='active' AND g.status='active' AND g.action='execute' AND g.capability=? AND g.resource_kind='execution-target' AND g.resource_id=? AND g.branch='human' AND g.role_id IN ('maintainer','infrastructure-admin','control-plane-admin')`, executorID, CIExternalDeploymentOperation, targetID).Scan(&count) != nil || count == 0 {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	return nil
}
