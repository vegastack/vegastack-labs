package recovery

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"testing"
)

func TestReplacementRestoreRunReportsDurableVerificationStage(t *testing.T) {
	for _, status := range []string{"planned", "fenced", "restoring", "verification-required"} {
		t.Run(status, func(t *testing.T) {
			service, request, planner, sessions, _ := operationsFixture(t)
			sessions.status = status
			run := operationsRunRequest(request, planner.qualification.Binding, "ack-a")
			got, err := service.Run(context.Background(), run, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod})
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != "verification-required" || sessions.status != "verification-required" {
				t.Fatalf("returned %s, journal %s", got.Status, sessions.status)
			}
		})
	}
}
