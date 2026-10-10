package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/runprotocol"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestApplyBoundRejectsChangedPlanBeforeEffect(t *testing.T) {
	for _, variant := range []string{"valid", "digest", "epoch"} {
		t.Run(variant, func(t *testing.T) {
			plan := clientPhase4Plan()
			in := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RecoveryEpoch: plan.Binding.RecoveryEpoch, IdempotencyKey: "bound-nonce", Extensions: []generated.ContractExtension{}}
			if variant == "digest" {
				in.PlanDigest = hostaction.BytesDigest([]byte("other-plan"))
			}
			if variant == "epoch" {
				in.RecoveryEpoch++
			}
			var effects atomic.Int32
			profile := servePhase4(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					writePhase4Envelope(t, w, "api.v1.plans.get", false, 2, 7, clientPlanPresentation(plan))
					return
				}
				effects.Add(1)
				run := clientPhase4Run(plan, runprotocol.ID(plan.PlanID, in.IdempotencyKey))
				writePhase4Envelope(t, w, "api.v1.plans.execute", true, 2, 7, clientRunPresentation(run))
			})
			_, err := NewClient(clientTestFactory()).ApplyBound(context.Background(), profile, in)
			if variant == "valid" {
				if err != nil || effects.Load() != 1 {
					t.Fatalf("valid apply: %v effects %d", err, effects.Load())
				}
			} else if err == nil || effects.Load() != 0 {
				t.Fatalf("stale plan reached effect: %v effects %d", err, effects.Load())
			}
		})
	}
}
