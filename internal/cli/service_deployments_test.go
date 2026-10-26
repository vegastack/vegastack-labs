package cli

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"strings"
	"testing"
)

type serviceDeploymentControlFixture struct {
	*stubControlOperations
	calls      int
	config, id string
	draft      generated.ServiceDeploymentDraftRequest
}

func (f *serviceDeploymentControlFixture) DraftServiceDeployment(_ context.Context, p string, in generated.ServiceDeploymentDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	f.calls++
	f.config = p
	f.draft = in
	return f.grantResponse, f.err
}
func (f *serviceDeploymentControlFixture) GetServiceDeployment(_ context.Context, p, id string) (localapi.TypedResponse[generated.ServiceDeploymentRecord], error) {
	f.calls++
	f.config = p
	f.id = id
	return localapi.TypedResponse[generated.ServiceDeploymentRecord]{Data: generated.ServiceDeploymentRecord{Request: generated.ServiceDeploymentRequest{Definition: generated.ServiceDefinition{ServiceID: id}}, Status: "partial"}, Raw: []byte("{\"deploymentFixture\":true}\n")}, f.err
}
func deploymentDraftJSON(t *testing.T) []byte {
	t.Helper()
	b, e := json.Marshal(generated.ServiceDeploymentDraftRequest{Schema: generated.SchemaIDServiceDeploymentDraftRequest, SchemaVersion: "1.0.0", ServiceID: "service-a", ArtifactID: "artifact-a", Action: "rollback", IdempotencyKey: "rollback-a", ReasonDigest: "sha256:" + strings.Repeat("a", 64)})
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestServiceDeploymentCLIUsesProtectedControl(t *testing.T) {
	for _, action := range []string{"draft", "show"} {
		f := &serviceDeploymentControlFixture{stubControlOperations: successfulControlOperations(t)}
		args := []string{"service", "deployment", action, "--config", "fixture/client.json"}
		if action == "draft" {
			args = append(args, "--file", "draft.json")
		} else {
			args = append(args, "--service-id", "service-a")
		}
		code, out, stderr := runTestAppWithOptions(t, context.Background(), args, nil, WithControlOperations(f, &stubFileReader{content: deploymentDraftJSON(t)}))
		if code != 0 || stderr != "" || f.calls != 1 || f.config != "fixture/client.json" {
			t.Fatalf("%d %s %s", code, out, stderr)
		}
		if action == "draft" && (f.draft.Action != "rollback" || !strings.Contains(out, "drafted")) {
			t.Fatal(out)
		}
	}
}
func TestServiceDeploymentCLIRejectsUnsafeInput(t *testing.T) {
	for _, args := range [][]string{{"show", "--service-id", "../other"}, {"draft", "--file", "draft.json"}, {"show", "--service-id", "service-a", "--url", "https://private"}} {
		f := &serviceDeploymentControlFixture{stubControlOperations: successfulControlOperations(t)}
		all := append([]string{"service", "deployment"}, args...)
		all = append(all, "--config", "profile.json")
		code, _, _ := runTestAppWithOptions(t, context.Background(), all, nil, WithControlOperations(f, &stubFileReader{content: []byte(`{"serviceId":"service-a","providerToken":"private"}`)}))
		if code == 0 || f.calls != 0 {
			t.Fatal(args)
		}
	}
}
