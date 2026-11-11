package plan

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
)

func TestDeploymentReconciliationReadablePlanExplicitlyDisclaimsRedeployment(t *testing.T) {
	p := generated.Plan{ServiceDeployment: &generated.ServiceDeploymentRequest{Action: "reconcile", Recovery: &generated.ServiceDeploymentRecovery{PriorRunID: "old-run", ProviderReceiptID: "selected-receipt"}}}
	text := readablePlan(p)
	for _, want := range []string{"Observe/reconcile existing deployment; no redeployment", "old-run", "selected-receipt", "original partial run remains historical"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing explicit intent %q", want)
		}
	}
}
