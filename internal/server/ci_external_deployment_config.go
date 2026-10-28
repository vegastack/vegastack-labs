package server

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// ciExternalDeploymentPolicies reuses artifacts already verified during startup.
func ciExternalDeploymentPolicies(p serverconfig.Profile, verified []servicecatalog.DeploymentPolicy) ([]store.CIExternalDeploymentPolicy, error) {
	bindings, err := serverconfig.FreezeCIExternalDeployments(p.CIExternalDeployments, p.CIJobBindings, p.ServiceBindings, p.ServiceDeploymentBindings)
	if err != nil {
		return nil, err
	}
	out := make([]store.CIExternalDeploymentPolicy, 0, len(bindings))
	for _, b := range bindings {
		policy := store.CIExternalDeploymentPolicy{Binding: b, ResolverID: b.ResolverID}
		for _, s := range p.ServiceBindings {
			if s.ServiceID == b.ServiceID {
				policy.Definition = serviceBindingDefinition(s)
			}
		}
		for _, d := range p.ServiceDeploymentBindings {
			if d.Binding.ServiceID == b.ServiceID {
				policy.ReferenceID = d.MutationReferenceID
				policy.ConfigurationDigest = d.Binding.ConfigurationDigest
			}
		}
		found := false
		for _, d := range verified {
			if d.Binding.ServiceID != b.ServiceID || d.Binding.ConfigurationDigest != policy.ConfigurationDigest {
				continue
			}
			for _, a := range d.Artifacts {
				if a.ArtifactID == b.ArtifactID {
					if found {
						return nil, serviceFailure(generated.ErrorCodeInputInvalid)
					}
					policy.Artifact = a
					found = true
				}
			}
		}
		if !found || policy.ReferenceID == "" || policy.ResolverID == "" {
			return nil, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
		}
		out = append(out, policy)
	}
	return out, nil
}
