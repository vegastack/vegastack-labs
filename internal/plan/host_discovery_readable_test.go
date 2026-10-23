package plan

import (
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestDiscoveryReadablePlanDisclosesAdministratorSerialRead(t *testing.T) {
	request := generated.HostDiscoveryTargetDraftRequest{
		Action: "activate",
		Target: generated.HostDiscoveryTarget{TargetID: "synthetic-target"},
	}
	plan := generated.Plan{HostDiscoveryTarget: &request}
	if strings.Contains(readablePlan(plan), "Administrator sudo identity read") {
		t.Fatal("default discovery describes sudo access")
	}
	request.Target.IdentityReadMode = new("administrator-sudo")
	body := readablePlan(plan)
	disclosure := "Administrator sudo identity read: later discovery uses existing sudo rights solely to read the hardware serial with the fixed command /usr/bin/sudo -n /usr/bin/cat /sys/class/dmi/id/product_serial. No permission changes."
	index := strings.Index(body, disclosure)
	jsonIndex := strings.Index(body, "Exact target and administrator confirmation:")
	if index < 0 || jsonIndex < 0 || index >= jsonIndex {
		t.Fatalf("serial-read disclosure missing before target JSON: %s", body)
	}
}
