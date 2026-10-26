package serverconfig

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicerecovery"
)

// FreezeServiceRecoveryProfiles seals exact provider targets and local custody
// configuration into an inert policy fingerprint computed only by the server.
func FreezeServiceRecoveryProfiles(input []generated.ServiceRecoveryProfile) ([]generated.ServiceRecoveryProfile, error) {
	if len(input) > 128 {
		return nil, servicerecovery.Invalid()
	}
	out := make([]generated.ServiceRecoveryProfile, 0, len(input))
	seen := map[string]bool{}
	for _, p := range input {
		if seen[p.Binding.PolicyID] || servicerecovery.ValidateProfile(p) != nil {
			return nil, servicerecovery.Invalid()
		}
		seen[p.Binding.PolicyID] = true
		p.Binding.ConfigurationDigest = ""
		p.Binding.ConfigurationDigest = servicerecovery.Digest(p)
		raw, e := json.Marshal(p)
		if e != nil || generated.ValidateContractJSON(generated.SchemaIDServiceRecoveryProfile, raw, generated.ContractExact) != nil {
			return nil, servicerecovery.Invalid()
		}
		var copy generated.ServiceRecoveryProfile
		if json.Unmarshal(raw, &copy) != nil {
			return nil, servicerecovery.Invalid()
		}
		out = append(out, copy)
	}
	return out, nil
}
