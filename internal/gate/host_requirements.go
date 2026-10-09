package gate

import (
	"encoding/json"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"slices"
)

var errHostAdmission = errors.New("host admission contract or binding invalid")

func RequiredHostControls(profile generated.HostProfile, stage string) ([]string, error) {
	if profile.OSFamily != "debian" || profile.OSVersion != "13.6" || profile.OSBuild != nil || profile.Architecture != "amd64" || profile.DefinitionVersion != "1.0.0" || profile.ProfileID == "" || (stage != "baseline" && stage != "role") || !slices.Contains([]string{"host", "control", "application", "ci", "recovery-spare", "reserve"}, profile.RoleID) {
		return nil, errHostAdmission
	}
	if stage == "role" && profile.RoleID == "host" {
		return nil, errHostAdmission
	}
	out := []string{}
	for _, r := range generated.GeneratedHostControlRequirements {
		if r.Stage == stage && slices.Contains(r.Roles, profile.RoleID) {
			out = append(out, r.ControlID)
		}
	}
	slices.Sort(out)
	if len(out) == 0 || len(out) > 64 {
		return nil, errHostAdmission
	}
	for i := 1; i < len(out); i++ {
		if out[i] == out[i-1] {
			return nil, errHostAdmission
		}
	}
	return out, nil
}
func DecodeHostControlResult(raw []byte) (generated.HostControlResult, error) {
	var out generated.HostControlResult
	if len(raw) == 0 || len(raw) > 16384 || generated.ValidateContractJSON(generated.SchemaIDHostControlResult, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &out) != nil {
		return out, errHostAdmission
	}
	return out, nil
}
