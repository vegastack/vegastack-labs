package cli

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"strings"
	"testing"
)

type serviceControlFixture struct {
	*stubControlOperations
	calls             int
	config, after, id string
	limit             int
	request           generated.ServiceImportDraftRequest
}

func (f *serviceControlFixture) ListServices(_ context.Context, p, after string, limit int) (localapi.TypedResponse[generated.ServiceList], error) {
	f.calls++
	f.config = p
	f.after = after
	f.limit = limit
	return localapi.TypedResponse[generated.ServiceList]{Data: generated.ServiceList{Services: []generated.ServiceRecord{}}, Raw: []byte("{\"serviceFixture\":true}\n")}, f.err
}
func (f *serviceControlFixture) GetService(_ context.Context, p, id string) (localapi.TypedResponse[generated.ServiceRecord], error) {
	f.calls++
	f.config = p
	f.id = id
	return localapi.TypedResponse[generated.ServiceRecord]{Data: generated.ServiceRecord{Definition: generated.ServiceDefinition{ServiceID: id}, RegistrationStatus: "registered", HostAdmission: "not-verified"}, Raw: []byte("{\"serviceFixture\":true}\n")}, f.err
}
func (f *serviceControlFixture) ObserveService(_ context.Context, p, id string) (localapi.TypedResponse[generated.ServiceObservation], error) {
	f.calls++
	f.config = p
	f.id = id
	return localapi.TypedResponse[generated.ServiceObservation]{Data: generated.ServiceObservation{ServiceID: id, HostingState: "unavailable", ArtifactState: "not-configured", ScanState: "unknown", SignatureState: "unverified", ProvenanceState: "unverified", RunningDigestState: "unknown", HealthState: "unknown", HostAdmission: "not-verified"}, Raw: []byte("{\"serviceFixture\":true}\n")}, f.err
}
func (f *serviceControlFixture) DraftServiceImport(_ context.Context, p string, input generated.ServiceImportDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	f.calls++
	f.config = p
	f.request = input
	return f.grantResponse, f.err
}
func serviceDraftJSON(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(generated.ServiceImportDraftRequest{Schema: generated.SchemaIDServiceImportDraftRequest, SchemaVersion: "1.0.0", ServiceID: "service-a", BindingID: "binding-a", IdempotencyKey: "import-a", ReasonDigest: "sha256:" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestServicesCLIUsesExactProtectedControl(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{{[]string{"list", "--after", "service-a", "--limit", "7"}, "No registered services"}, {[]string{"show", "--service-id", "service-a"}, "not-verified"}, {[]string{"observe", "--service-id", "service-a"}, "unverified"}, {[]string{"import", "draft", "--file", "draft.json"}, "drafted"}} {
		f := &serviceControlFixture{stubControlOperations: successfulControlOperations(t)}
		args := append([]string{"service"}, tc.args...)
		args = append(args, "--config", "fixture/client.json")
		code, out, stderr := runTestAppWithOptions(t, context.Background(), args, nil, WithControlOperations(f, &stubFileReader{content: serviceDraftJSON(t)}))
		if code != 0 || stderr != "" || f.calls != 1 || f.config != "fixture/client.json" || !strings.Contains(out, tc.want) {
			t.Fatalf("%v code=%d out=%s stderr=%s fixture=%+v", args, code, out, stderr, f)
		}
		if tc.args[0] == "list" && (f.after != "service-a" || f.limit != 7) {
			t.Fatal(f)
		}
		if tc.args[0] == "import" && f.request.ServiceID != "service-a" {
			t.Fatal(f)
		}
	}
}
func TestServicesCLIRejectsUnboundedInputBeforeControl(t *testing.T) {
	for _, args := range [][]string{{"list", "--limit", "0"}, {"list", "--limit", "101"}, {"list", "--after", "../secret"}, {"show", "--service-id", "../secret"}, {"observe", "--service-id", "service-a", "--url", "https://invalid.example"}, {"import", "draft", "--file", "draft.json"}} {
		f := &serviceControlFixture{stubControlOperations: successfulControlOperations(t)}
		all := append([]string{"service"}, args...)
		all = append(all, "--config", "fixture/client.json", "--output", "json")
		code, _, _ := runTestAppWithOptions(t, context.Background(), all, nil, WithControlOperations(f, &stubFileReader{content: []byte(`{"serviceId":"service-a","url":"https://invalid.example"}`)}))
		if code == 0 || f.calls != 0 {
			t.Fatalf("accepted %v calls=%d", args, f.calls)
		}
	}
}
func TestServicesCLIForwardsExactJSONAndDenial(t *testing.T) {
	f := &serviceControlFixture{stubControlOperations: successfulControlOperations(t)}
	code, out, _ := runTestAppWithOptions(t, context.Background(), []string{"service", "show", "--config", "profile.json", "--service-id", "service-a", "--output", "json"}, nil, WithControlOperations(f, nil))
	if code != 0 || strings.TrimSpace(out) != `{"serviceFixture":true}` {
		t.Fatal(code, out)
	}
	f.err = failure.New(generated.ErrorCodeAuthorizationDenied, "effective-authorization", false)
	code, out, _ = runTestAppWithOptions(t, context.Background(), []string{"service", "observe", "--config", "profile.json", "--service-id", "service-a", "--output", "json"}, nil, WithControlOperations(f, nil))
	if code == 0 || strings.Contains(out, "serviceFixture") {
		t.Fatal(code, out)
	}
}

func (s *stubControlOperations) ListServices(ctx context.Context, p, after string, limit int) (localapi.TypedResponse[generated.ServiceList], error) {
	return (&serviceControlFixture{stubControlOperations: s}).ListServices(ctx, p, after, limit)
}
func (s *stubControlOperations) GetService(ctx context.Context, p, id string) (localapi.TypedResponse[generated.ServiceRecord], error) {
	return (&serviceControlFixture{stubControlOperations: s}).GetService(ctx, p, id)
}
func (s *stubControlOperations) ObserveService(ctx context.Context, p, id string) (localapi.TypedResponse[generated.ServiceObservation], error) {
	return (&serviceControlFixture{stubControlOperations: s}).ObserveService(ctx, p, id)
}
func (s *stubControlOperations) DraftServiceImport(ctx context.Context, p string, input generated.ServiceImportDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	return s.grantResponse, s.err
}
