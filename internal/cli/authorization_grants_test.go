package cli

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"strings"
	"testing"
)

type grantControlFixture struct {
	*stubControlOperations
	called int
}

func (f *grantControlFixture) DraftAuthorizationGrants(context.Context, string, generated.AuthorizationGrantBatchRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	f.called++
	return localapi.TypedResponse[generated.DeclarationRevision]{}, nil
}
func TestGrantBatchCLIRejectsMalformedInputWithoutTransport(t *testing.T) {
	f := &grantControlFixture{stubControlOperations: successfulControlOperations(t)}
	files := &stubFileReader{content: []byte(`{"unknown":"private-canary"}`)}
	code, out, _ := runTestAppWithOptions(t, context.Background(), []string{"authorization", "grants", "draft", "--config", "fixture.json", "--file", "request.json", "--output", "json"}, nil, WithControlOperations(f, files))
	if code == 0 || f.called != 0 || files.limit != 32768 || !strings.Contains(out, "INPUT_INVALID") || strings.Contains(out, "private-canary") {
		t.Fatalf("unsafe handling code=%d calls=%d limit=%d output=%s", code, f.called, files.limit, out)
	}
}
