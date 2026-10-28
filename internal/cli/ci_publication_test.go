package cli

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"strings"
	"testing"
)

type ciPublicationControlFixture struct {
	*stubControlOperations
	calls   int
	config  string
	request generated.CiPublicationDraftRequest
}

func (f *ciPublicationControlFixture) DraftCIPublication(_ context.Context, config string, in generated.CiPublicationDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	f.calls++
	f.config = config
	f.request = in
	return f.grantResponse, nil
}
func TestCIPublicationCLIThinDraft(t *testing.T) {
	in := generated.CiPublicationDraftRequest{Schema: generated.SchemaIDCiPublicationDraftRequest, SchemaVersion: "1.0.0", BindingID: "publish-a", IdempotencyKey: "job-a", ReasonDigest: "sha256:" + strings.Repeat("a", 64)}
	raw, _ := json.Marshal(in)
	f := &ciPublicationControlFixture{stubControlOperations: successfulControlOperations(t)}
	code, out, stderr := runTestAppWithOptions(t, context.Background(), []string{"ci", "publication", "draft", "--config", "profile.json", "--file", "draft.json"}, nil, WithControlOperations(f, &stubFileReader{content: raw}))
	if code != 0 || stderr != "" || !strings.Contains(out, "Draft declaration") || f.calls != 1 || f.config != "profile.json" || f.request != in {
		t.Fatal(code, out, stderr, f)
	}
	f.calls = 0
	code, _, _ = runTestAppWithOptions(t, context.Background(), []string{"ci", "publication", "draft", "--config", "profile.json", "--file", "draft.json"}, nil, WithControlOperations(f, &stubFileReader{content: []byte(`{"runId":"60","command":"unsafe"}`)}))
	if code == 0 || f.calls != 0 {
		t.Fatal("untyped execution input reached API")
	}
}
