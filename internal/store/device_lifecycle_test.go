package store

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"testing"
)

func deviceFixture(action string) generated.AuthorizationGrantBatchRequest {
	in := lifecycleFixture("")
	in.DeviceAction = action
	in.DeviceID = "device.synthetic"
	if action != "request" {
		in.ExpectedDeviceRevision = 1
	}
	return in
}
func TestDeviceLifecycleInputAndSelfApproval(t *testing.T) {
	ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "new-human", Method: identity.LocalOSPeerMethod})
	for _, action := range []string{"request", "approve", "revoke"} {
		in := deviceFixture(action)
		if e := ValidateAuthorizationGrantBatch(in); e != nil {
			t.Fatal(action, e)
		}
		e := validateLifecycleActor(ctx, in)
		if action == "request" && e != nil || action != "request" && Code(e) != generated.ErrorCodeAuthorizationDenied {
			t.Fatal(action, e)
		}
		in.LifecycleAction = "suspend"
		if ValidateAuthorizationGrantBatch(in) == nil {
			t.Fatal("mixed lifecycle accepted")
		}
		in = deviceFixture(action)
		in.DeviceID = ""
		if ValidateAuthorizationGrantBatch(in) == nil {
			t.Fatal("implicit device accepted")
		}
		in = deviceFixture(action)
		in.ExpectedDeviceRevision = 0
		if action != "request" && ValidateAuthorizationGrantBatch(in) == nil {
			t.Fatal("implicit revision accepted")
		}
	}
	in := lifecycleFixture("suspend")
	in.DeviceID = "unattributed"
	if ValidateAuthorizationGrantBatch(in) == nil {
		t.Fatal("orphan device metadata accepted")
	}
}
