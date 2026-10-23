package store

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"strings"
	"testing"
)

func lifecycleFixture(action string) generated.AuthorizationGrantBatchRequest {
	rev := int64(1)
	if action == "onboard" {
		rev = 0
	}
	return generated.AuthorizationGrantBatchRequest{Schema: generated.SchemaIDAuthorizationGrantBatchRequest, SchemaVersion: "1.0.0", PrincipalID: "new-human", LifecycleAction: action, ExpectedGrantRevision: rev, IdempotencyKey: "lifecycle", ReasonDigest: "sha256:" + strings.Repeat("a", 64), Changes: []generated.AuthorizationGrantChange{}}
}
func TestUserLifecycleInputAndSelfDenial(t *testing.T) {
	for _, action := range []string{"onboard", "suspend", "resume", "offboard"} {
		in := lifecycleFixture(action)
		if err := ValidateAuthorizationGrantBatch(in); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: in.PrincipalID, Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman})
		if err := validateLifecycleActor(ctx, in); Code(err) != generated.ErrorCodeAuthorizationDenied {
			t.Fatalf("self %s accepted: %v", action, err)
		}
		in.ExpectedGrantRevision = 0
		if action == "onboard" {
			in.ExpectedGrantRevision = 1
		}
		if ValidateAuthorizationGrantBatch(in) == nil {
			t.Fatalf("%s revision mismatch accepted", action)
		}
	}
	if ValidateAuthorizationGrantBatch(lifecycleFixture("")) == nil {
		t.Fatal("empty ordinary grant batch accepted")
	}
}
