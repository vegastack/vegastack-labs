package run

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
)

func TestControllerSetupDeferralIsOnlyExactHumanCentralOperation(t *testing.T) {
	for _, variant := range []string{"exact", "external", "preauthorized", "idempotent", "adapter", "operation", "multiple", "host-action", "host-role", "access", "digest"} {
		t.Run(variant, func(t *testing.T) {
			d := "sha256:" + strings.Repeat("a", 64)
			p := generated.Plan{AuthorizationBranch: "human", ExecutorMode: "central", Operations: []generated.PlanOperation{{AdapterID: "core.controller-setup", OperationType: "controller.setup.bootstrap", InputDigest: d, ArtifactDigest: d}}}
			switch variant {
			case "external":
				p.ExecutorMode = "external"
			case "preauthorized":
				p.AuthorizationBranch = "preauthorized"
			case "idempotent":
				p.Operations[0].Idempotent = true
			case "adapter":
				p.Operations[0].AdapterID = "host-action"
			case "operation":
				p.Operations[0].OperationType = "control-plane.change"
			case "multiple":
				p.Operations = append(p.Operations, p.Operations[0])
			case "host-action":
				p.HostAction = &generated.HostActionRequest{}
			case "host-role":
				p.HostRoleScope = &generated.HostRoleScope{}
			case "access":
				p.HostAccessSequence = &generated.HostAccessSequence{}
			case "digest":
				p.Operations[0].InputDigest = strings.Repeat("x", 71)
			}
			if got := ControllerSetupPlan(p); got != (variant == "exact") {
				t.Fatal("unexpected deferral", variant, got)
			}
		})
	}
}
