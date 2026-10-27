package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"reflect"
	"testing"
)

func TestCIJobRemoteArgumentsAreExact(t *testing.T) {
	s := requestSpec{command: "api.v1.ci.jobs.drafts.create", path: "/api/v1/ci/jobs/drafts"}
	if got := remoteCommandArguments(s); !reflect.DeepEqual(got, []string{"ci", "job", "draft"}) {
		t.Fatal(got)
	}
	for _, path := range []string{"https://private.invalid/api/v1/ci/jobs/drafts", "/api/v1/ci/jobs/drafts?allow=true", "/api/v1/ci/jobs/drafts/../allow"} {
		s.path = path
		if remoteCommandArguments(s) != nil {
			t.Fatal("unbound remote path accepted")
		}
	}
	if _, e := NewClient(clientTestFactory()).DraftCIJob(context.Background(), serverconfig.Profile{}, generated.CiJobDraftRequest{}); e == nil {
		t.Fatal("invalid request reached transport")
	}
}
