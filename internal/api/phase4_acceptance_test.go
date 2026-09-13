//go:build linux

package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func TestPhase4AcceptanceExternalExecutorCannotStealOrWidenWork(t *testing.T) {
	fixture := newExecutorSQLiteFixture(t)
	wrongPrincipal := identity.Principal{ID: "executor-acceptance-wrong", Method: identity.CloudflareAccessMethod, Kind: identity.PrincipalPolicy}
	wrong := fixture.claimRequest(fixture.adapterID, "acceptance-theft")
	wrong.PrincipalID = wrongPrincipal.ID
	denied := fixture.post(wrong, "/api/v1/executor-leases/claim", wrongPrincipal)
	assertResultError(t, denied, http.StatusForbidden, generated.ErrorCodeAuthorizationDenied)
	if strings.Contains(denied.body, fixture.plan.Operations[0].ArtifactDigest) || strings.Contains(denied.body, fixture.plan.Operations[0].OperationID) {
		t.Fatalf("denied executor learned protected work: %s", denied.body)
	}

	lease := decodeResultData[generated.ExecutorLease](t, fixture.post(fixture.claimRequest(fixture.adapterID, "acceptance-claim"), "/api/v1/executor-leases/claim", fixture.principal), http.StatusOK)
	widened := fixture.receipt(lease, "acceptance-widened-receipt")
	widened.Receipt.TargetID = "target-acceptance-widened"
	response := fixture.post(widened, "/api/v1/execution-receipts", fixture.principal)
	assertResultError(t, response, http.StatusConflict, generated.ErrorCodeRecoveryRequired)
	current, err := fixture.runs.GetRun(context.Background(), fixture.running.RunID)
	if err != nil || current.Status != "partial" || current.RollbackStatus != "required" || current.VerificationStatus != "incomplete" || current.Steps[0].EffectState != "effect-unknown" {
		t.Fatalf("widened receipt changed durable work: %#v, %v", current, err)
	}
}
