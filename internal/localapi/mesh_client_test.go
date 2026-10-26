package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
)

func TestMeshStatusRejectsWrongProfileOrEpoch(t *testing.T) {
	for _, variant := range []string{"own", "profile", "epoch"} {
		t.Run(variant, func(t *testing.T) {
			d := generated.MeshStatusData{Schema: generated.SchemaIDMeshStatusData, SchemaVersion: "1.0.0", ProfileID: "pilot", Status: "unknown", Reason: "no-provider-observation", ObservationDigest: "sha256:" + strings.Repeat("a", 64), StateRevision: 4, RecoveryEpoch: 0}
			if variant == "profile" {
				d.ProfileID = "other"
			}
			if variant == "epoch" {
				d.RecoveryEpoch = 1
			}
			_, p, captured := serveFixedResponse(t, 200, operationEnvelope(t, "api.v1.network.mesh.status", false, 0, 4, d))
			_, e := NewClient(clientTestFactory()).MeshStatus(context.Background(), p, "pilot")
			select {
			case <-captured:
			default:
				t.Fatal("no typed request")
			}
			if (e == nil) != (variant == "own") {
				t.Fatalf("%s: %v", variant, e)
			}
		})
	}
}
