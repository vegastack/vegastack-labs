package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"net/http"
	"testing"
)

func TestPlanApprovalRejectsCrossPlanAndEpochResponses(t *testing.T) {
	for _, variant := range []string{"valid", "other-plan", "other-digest", "other-epoch"} {
		t.Run(variant, func(t *testing.T) {
			in := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: "plan-native", PlanDigest: hostaction.Digest("plan"), RecoveryEpoch: 7, IdempotencyKey: "request-native", Extensions: []generated.ContractExtension{}}
			profile := servePhase4(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/api/v1/plans/plan-native/approval-request" {
					t.Errorf("unexpected route %s %s", r.Method, r.URL.Path)
				}
				d := generated.ApprovalStatus{Schema: generated.SchemaIDApprovalStatus, SchemaVersion: "1.0.0", PlanID: in.PlanID, PlanDigest: in.PlanDigest, Status: "pending", Channel: "slack", Owner: "assigned-maintainer", StateRevision: 2, RecoveryEpoch: 7, ExpiresAt: "2026-10-09T19:00:00Z", ObservedAt: "2026-10-09T18:00:00Z"}
				switch variant {
				case "other-plan":
					d.PlanID = "plan-other"
				case "other-digest":
					d.PlanDigest = hostaction.Digest("other")
				case "other-epoch":
					d.RecoveryEpoch = 8
				}
				writePhase4Envelope(t, w, "api.v1.plans.approval-request.create", true, d.RecoveryEpoch, 2, d)
			})
			_, err := NewClient(clientTestFactory()).RequestPlanApproval(context.Background(), profile, in)
			if variant == "valid" && err != nil {
				t.Fatal(err)
			}
			if variant != "valid" && err == nil {
				t.Fatal("substituted approval accepted")
			}
		})
	}
}
