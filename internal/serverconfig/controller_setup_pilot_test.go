package serverconfig

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
)

func TestControllerSetupPolicyRequiresExactDedicatedSelection(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	good := generated.ControllerSetupPilotPolicy{Schema: generated.SchemaIDControllerSetupPilotPolicy, SchemaVersion: "1.0.0", HostID: "synthetic-controller", HostIdentityDigest: d, ControllerMachineIDDigest: d, ControllerInstanceID: "instance-a", AppliedProfileID: "profile-a", RecoveryEpoch: 0, RecoveryImageDigest: d, AdministratorUID: 1000, AdministratorPrincipalID: "operator-a", ServiceUID: 2000, ServiceGID: 2000, ExecutableDigest: d, ExpiresAt: "2026-10-28T12:00:00Z"}
	if !ValidControllerSetupPilot(good) {
		t.Fatal("complete protected selection denied")
	}
	for _, variant := range []string{"node04", "node05", "node_4", "missing-image", "missing-machine", "same-account", "root-admin", "root-service", "missing-principal"} {
		t.Run(variant, func(t *testing.T) {
			p := good
			switch variant {
			case "node04", "node05", "node_4":
				p.HostID = variant
			case "missing-image":
				p.RecoveryImageDigest = ""
			case "missing-machine":
				p.ControllerMachineIDDigest = ""
			case "same-account":
				p.ServiceUID = p.AdministratorUID
			case "root-admin":
				p.AdministratorUID = 0
			case "root-service":
				p.ServiceUID = 0
			case "missing-principal":
				p.AdministratorPrincipalID = ""
			}
			if ValidControllerSetupPilot(p) {
				t.Fatal("unsafe policy accepted")
			}
		})
	}
}
