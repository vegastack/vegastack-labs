//go:build linux

package linuxrole

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestNativeHandoffObservationRequiresFreshSameAuthority(t *testing.T) {
	n, _, calls := handoffFixture(t)
	if _, err := n.inspectNativeControlHandoff(context.Background()); err == nil {
		t.Fatal("pending handoff qualified")
	}
	if err := n.runHandoff(context.Background()); err != nil {
		t.Fatal(err)
	}
	prior := len(*calls)
	observed, err := n.inspectNativeControlHandoff(context.Background())
	if err != nil || observed.ReceiptDigest == "" || !observed.CurrentState.ServiceActive || len(*calls) != prior {
		t.Fatalf("read-only completed observation: %+v %v", observed, err)
	}
	good := n.handoffHooks.state
	for _, mode := range []string{"inactive", "epoch", "instance", "writer", "unhealthy"} {
		t.Run(mode, func(t *testing.T) {
			n.handoffHooks.state = func(ctx context.Context, in generated.LinuxRoleInput) (ControlServiceState, error) {
				s, e := good(ctx, in)
				switch mode {
				case "inactive":
					s.ServiceActive = false
				case "epoch":
					s.RecoveryEpoch++
				case "instance":
					s.DatabaseInstanceID = "other"
				case "writer":
					s.WriterLockDigest = "other"
				case "unhealthy":
					s.Healthy = false
				}
				return s, e
			}
			if _, err := n.inspectNativeControlHandoff(context.Background()); err == nil {
				t.Fatal("changed current authority qualified")
			}
		})
	}
}
