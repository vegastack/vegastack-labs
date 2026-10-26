package serverconfig

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
)

// FreezeDeploymentBindings binds the finite adapter configuration into the
// generic deployment policy. The digest is computed by the server, not a CLI.
func FreezeDeploymentBindings(input []generated.ServiceDeploymentProviderBinding, services []generated.ServiceProviderBinding) ([]generated.ServiceDeploymentProviderBinding, error) {
	invalid := func() ([]generated.ServiceDeploymentProviderBinding, error) {
		return nil, failure.New(generated.ErrorCodeInputInvalid, "service-deployment-bindings", false)
	}
	if len(input) > 128 {
		return invalid()
	}
	out := make([]generated.ServiceDeploymentProviderBinding, 0, len(input))
	seen := map[string]bool{}
	for _, b := range input {
		if seen[b.Binding.ServiceID] || !b.ExclusiveOwnership || !serviceProviderID.MatchString(b.DestinationUUID) || !serviceProviderID.MatchString(b.ServerUUID) || b.ServerID < 1 || len(b.Artifacts) == 0 || len(b.Artifacts) > 128 {
			return invalid()
		}
		var service *generated.ServiceProviderBinding
		for i := range services {
			if services[i].BindingID == b.ServiceBindingID {
				service = &services[i]
				break
			}
		}
		if service == nil || service.ServiceID != b.Binding.ServiceID || b.Binding.BindingID != service.BindingID || service.Coolify == nil || service.Coolify.DestinationType != "App\\Models\\StandaloneDocker" || service.Harbor == nil {
			return invalid()
		}
		origin, err := url.Parse(service.Harbor.Origin)
		if err != nil || origin.Host == "" {
			return invalid()
		}
		if b.Configuration != nil {
			if servicecatalog.ValidateConfiguration(*b.Configuration) != nil {
				return invalid()
			}
			configuration := *b.Configuration
			configuration.SecretReferenceIDs = append([]string{}, b.Configuration.SecretReferenceIDs...)
			b.Configuration = &configuration
		}
		if len(b.EnvironmentSecrets) > 32 {
			return invalid()
		}
		b.EnvironmentSecrets = append([]generated.ServiceEnvironmentSecret(nil), b.EnvironmentSecrets...)
		names, refs := map[string]bool{}, map[string]bool{}
		for _, secret := range b.EnvironmentSecrets {
			if !regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`).MatchString(secret.Name) || names[secret.Name] || refs[secret.ReferenceID] || secret.ExpectedFingerprint == "" {
				return invalid()
			}
			names[secret.Name] = true
			refs[secret.ReferenceID] = true
		}
		if b.Configuration != nil {
			if len(refs) != len(b.Configuration.SecretReferenceIDs) {
				return invalid()
			}
			for _, id := range b.Configuration.SecretReferenceIDs {
				if !refs[id] {
					return invalid()
				}
			}
		} else if len(refs) > 0 {
			return invalid()
		}
		b.Artifacts = append([]generated.ServiceDeploymentArtifactSource(nil), b.Artifacts...)
		ids := map[string]bool{}
		for _, a := range b.Artifacts {
			if ids[a.ArtifactID] || a.Repository != origin.Host+"/"+service.Harbor.Project+"/"+service.Harbor.Repository || !strings.HasPrefix(a.Digest, "sha256:") {
				return invalid()
			}
			ids[a.ArtifactID] = true
			for _, p := range []string{a.ManifestPath, a.BundlePath, a.PolicyPath} {
				if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == string(filepath.Separator) || strings.ContainsRune(p, 0) {
					return invalid()
				}
			}
		}
		b.Binding.ConfigurationDigest = ""
		b.Binding.ConfigurationDigest = servicecatalog.Digest(b)
		raw, err := json.Marshal(b)
		if err != nil || generated.ValidateContractJSON(generated.SchemaIDServiceDeploymentProviderBinding, raw, generated.ContractExact) != nil {
			return invalid()
		}
		seen[b.Binding.ServiceID] = true
		out = append(out, b)
	}
	return out, nil
}
