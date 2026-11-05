package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"reflect"
	"testing"
)

func TestManualPublicationRemoteArgumentsAreExact(t *testing.T) {
	s := requestSpec{command: "api.v1.artifact.publications.drafts.create", path: "/api/v1/artifacts/publications/drafts"}
	if got := remoteCommandArguments(s); !reflect.DeepEqual(got, []string{"artifact", "publication", "draft"}) {
		t.Fatal(got)
	}
	for _, path := range []string{"https://private.invalid/api/v1/artifacts/publications/drafts", "/api/v1/artifacts/publications/drafts?allow=true", "/api/v1/artifacts/publications/drafts/../allow"} {
		s.path = path
		if remoteCommandArguments(s) != nil {
			t.Fatal("unbound remote path accepted")
		}
	}
	if _, e := NewClient(clientTestFactory()).DraftManualPublication(context.Background(), serverconfig.Profile{}, generated.ManualPublicationDraftRequest{}); e == nil {
		t.Fatal("invalid request reached transport")
	}
}
