package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"reflect"
	"testing"
)

func TestCIPublicationRemoteArgumentsAreExact(t *testing.T) {
	s := requestSpec{command: "api.v1.ci.publications.drafts.create", path: "/api/v1/ci/publications/drafts"}
	if got := remoteCommandArguments(s); !reflect.DeepEqual(got, []string{"ci", "publication", "draft"}) {
		t.Fatal(got)
	}
	for _, path := range []string{"https://private.invalid/api/v1/ci/publications/drafts", "/api/v1/ci/publications/drafts?allow=true", "/api/v1/ci/publications/drafts/../allow"} {
		s.path = path
		if remoteCommandArguments(s) != nil {
			t.Fatal("unbound remote path accepted")
		}
	}
	if _, e := NewClient(clientTestFactory()).DraftCIPublication(context.Background(), serverconfig.Profile{}, generated.CiPublicationDraftRequest{}); e == nil {
		t.Fatal("invalid request reached transport")
	}
}
