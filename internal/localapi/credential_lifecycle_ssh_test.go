package localapi

import (
	"reflect"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
)

func TestCredentialLifecycleSSHArgumentsFollowTypedAction(t *testing.T) {
	spec := requestSpec{method: localtransport.MethodPost, path: "/api/v1/credential-lifecycle-drafts", command: "api.v1.credential-lifecycle-drafts.create"}
	for _, action := range []string{"stage", "activate", "rotate", "revoke", "recover"} {
		got := remoteCommandArgumentsForInput(spec, generated.CredentialLifecycleRequest{Action: "credential." + action})
		want := []string{"credential", action}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s SSH arguments = %v, want %v", action, got, want)
		}
	}
	if got := remoteCommandArgumentsForInput(spec, generated.CredentialLifecycleRequest{Action: "credential.import"}); got != nil {
		t.Fatalf("private import acquired lifecycle SSH arguments: %v", got)
	}
}
