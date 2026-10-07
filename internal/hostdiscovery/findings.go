package hostdiscovery

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"sort"
	"strings"
)

var Operations = []string{"os-release", "debian-version", "architecture", "machine-id", "product-uuid", "product-serial", "memory", "cpu-online", "block-devices", "interfaces"}

func ValidateCollection(c Collection) error {
	if len(c.Facts) > 768 || len(c.Missing) > len(Operations) {
		return Error(generated.ErrorCodeInputInvalid)
	}
	seen := map[string]bool{}
	ops := map[string]bool{}
	for _, op := range Operations {
		ops[op] = true
	}
	for _, f := range c.Facts {
		raw, _ := json.Marshal(f)
		if !ops[f.Operation] || seen[f.Name] || generated.ValidateContractJSON(generated.SchemaIDHostDiscoveryFact, raw, generated.ContractExact) != nil || strings.ContainsAny(f.Value, "\x00\r\n\t") {
			return Error(generated.ErrorCodeInputInvalid)
		}
		seen[f.Name] = true
	}
	missing := map[string]bool{}
	for _, op := range c.Missing {
		if !ops[op] || missing[op] {
			return Error(generated.ErrorCodeInputInvalid)
		}
		missing[op] = true
	}
	return nil
}
func Findings(target generated.HostDiscoveryTarget, c Collection) []string {
	result := []string{"hardening-unverified", "role-admission-unverified", "physical-inspection-missing", "disk-health-missing", "thermal-qualification-missing", "power-loss-proof-missing", "identity-class-unverified"}
	facts := map[string]string{}
	observed := map[string]bool{}
	for _, f := range c.Facts {
		facts[f.Name] = f.Value
		observed[f.Operation] = true
	}
	for _, op := range Operations {
		if !observed[op] {
			result = append(result, "missing-"+op)
		}
	}
	versionFact := "os.version"
	if strings.Contains(target.ExpectedVersion, ".") {
		versionFact = "os.point-version"
	}
	for _, item := range []struct{ name, want, code string }{{"os.id", target.ExpectedOS, "os-mismatch"}, {versionFact, target.ExpectedVersion, "os-version-mismatch"}, {"architecture", target.ExpectedArchitecture, "architecture-mismatch"}} {
		if got := facts[item.name]; got != "" && got != item.want {
			result = append(result, item.code)
		}
	}
	if facts["os.id"] != "debian" || facts["os.version"] != "13" || facts["architecture"] != "amd64" {
		result = append(result, "unsupported-profile")
	}
	sort.Strings(result)
	return result
}
