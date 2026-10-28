package serverconfig

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"time"
)

// Explicit protected policy only; no default host or fixture activation.
func ValidControllerSetupPilot(p generated.ControllerSetupPilotPolicy) bool {
	raw, e := json.Marshal(p)
	expiry, te := time.Parse(time.RFC3339, p.ExpiresAt)
	return e == nil && generated.ValidateContractJSON(generated.SchemaIDControllerSetupPilotPolicy, raw, generated.ContractExact) == nil && !controllerSetupExcludedHost(p.HostID) && p.AdministratorUID > 0 && p.AdministratorUID <= 4294967295 && p.ServiceUID != p.AdministratorUID && p.ServiceUID > 0 && p.ServiceUID <= 4294967295 && p.ServiceGID > 0 && p.ServiceGID <= 4294967295 && te == nil && !expiry.IsZero()
}

func controllerSetupExcludedHost(host string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "", "_", "", ".", "").Replace(host))
	switch normalized {
	case "vsknode04", "vsknode05", "node04", "node05", "node4", "node5":
		return true
	}
	return false
}
