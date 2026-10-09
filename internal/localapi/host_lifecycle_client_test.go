package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestHostLifecycleClientRejectsInvalidBeforeTransport(t *testing.T) {
	profile, captured := serveGateCheckResponses(t, "G-001", nil, nil)
	client := NewClient(clientTestFactory())
	calls := []func() error{
		func() error {
			_, e := client.PrepareHostTarget(context.Background(), profile, generated.HostDiscoveryTargetDraftRequest{})
			return e
		},
		func() error {
			_, e := client.SubmitHostAction(context.Background(), profile, generated.HostActionRequest{})
			return e
		},
		func() error {
			_, e := client.SubmitHostAccess(context.Background(), profile, generated.HostAccessDraftRequest{})
			return e
		},
		func() error { _, e := client.GetHostObservation(context.Background(), profile, "../outside"); return e },
	}
	for i, call := range calls {
		if call() == nil {
			t.Fatalf("invalid request %d accepted", i)
		}
	}
	select {
	case request := <-captured:
		t.Fatalf("invalid request reached transport: %+v", request)
	default:
	}
}
