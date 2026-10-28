package serverconfig

import (
	"encoding/json"
	"net/netip"
	"net/url"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
)

// FreezeCIExternalDeployments selects existing immutable deployment inputs.
// DNS and payload reachability are checked again by the runtime before secrets.
func FreezeCIExternalDeployments(input []generated.CiExternalDeploymentBinding, jobs []generated.CiJobExecutionBinding, services []generated.ServiceProviderBinding, deployments []generated.ServiceDeploymentProviderBinding) ([]generated.CiExternalDeploymentBinding, error) {
	invalid := func() ([]generated.CiExternalDeploymentBinding, error) {
		return nil, failure.New(generated.ErrorCodeInputInvalid, "ci-external-deployment", false)
	}
	if len(input) > 64 {
		return invalid()
	}
	out := append([]generated.CiExternalDeploymentBinding(nil), input...)
	seen, executions := map[string]bool{}, map[string]bool{}
	for _, b := range out {
		raw, err := json.Marshal(b)
		if err != nil || generated.ValidateContractJSON(generated.SchemaIDCiExternalDeploymentBinding, raw, generated.ContractExact) != nil || seen[b.BindingID] || executions[b.ExecutionBindingID] {
			return invalid()
		}
		seen[b.BindingID] = true
		executions[b.ExecutionBindingID] = true
		jobOK := false
		for _, j := range jobs {
			if j.BindingID == b.ExecutionBindingID && j.AutomationPrincipalID == b.ExecutorID {
				jobOK = true
			}
		}
		if !jobOK {
			return invalid()
		}
		var service *generated.ServiceProviderBinding
		for i := range services {
			if services[i].ServiceID == b.ServiceID {
				if service != nil {
					return invalid()
				}
				service = &services[i]
			}
		}
		if service == nil || service.Coolify == nil {
			return invalid()
		}
		u, err := url.Parse(service.Coolify.Origin)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/" && u.Path != "/api/v1") || (u.Port() != "" && u.Port() != "443") {
			return invalid()
		}
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
			return invalid()
		}
		if ip, e := netip.ParseAddr(host); e == nil && (!ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || !ip.Is4()) {
			return invalid()
		}
		found := false
		for _, d := range deployments {
			if d.Binding.ServiceID != b.ServiceID {
				continue
			}
			if found || d.ServiceBindingID != service.BindingID || !d.ExclusiveOwnership || d.Configuration == nil || servicecatalog.ValidateConfiguration(*d.Configuration) != nil || len(d.Configuration.SecretReferenceIDs) != 0 || len(d.EnvironmentSecrets) != 0 {
				return invalid()
			}
			for _, a := range d.Artifacts {
				if a.ArtifactID == b.ArtifactID {
					if found {
						return invalid()
					}
					found = true
				}
			}
		}
		if !found {
			return invalid()
		}
	}
	return out, nil
}
