package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
)

type credentialImportServiceStub struct {
	preflight func(context.Context, generated.CredentialImportRequest, identity.Principal) (*generated.CredentialImportSubmission, error)
	importer  func(context.Context, generated.CredentialImportRequest, []byte, identity.Principal) (generated.CredentialImportSubmission, error)
}

func (stub credentialImportServiceStub) Preflight(ctx context.Context, input generated.CredentialImportRequest, principal identity.Principal) (*generated.CredentialImportSubmission, error) {
	return stub.preflight(ctx, input, principal)
}
func (stub credentialImportServiceStub) Import(ctx context.Context, input generated.CredentialImportRequest, private []byte, principal identity.Principal) (generated.CredentialImportSubmission, error) {
	return stub.importer(ctx, input, private, principal)
}

func credentialImportTestApp(t *testing.T, service credentialImportServiceStub) *Application {
	t.Helper()
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "0.0.0-test", ReleaseBuildID: "build-test"}, func() (string, error) { return "request-credential-test", nil })
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: allowOperationAuthorizer(), Reads: testReads{}, Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	effective := &effectiveAuthorizationStub{}
	app.effective = EffectiveAuthorizationConfig{Authorizer: effective, Recorder: effective, Clock: time.Now}
	if err := RegisterCredentialImportOperation(app, CredentialImportOperations{Imports: service, Results: factory}); err != nil {
		t.Fatal(err)
	}
	return app
}

func credentialImportInput() generated.CredentialImportRequest {
	value := generated.CredentialImportRequest{Schema: generated.SchemaIDCredentialImportRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 0, RecoveryEpoch: 0, IdempotencyKey: "import-a", ReferenceID: "ref-a", ConsumerID: "consumer-a", PurposeID: "purpose-a", TargetID: "target-a", ResolverID: "native-systemd", MaterialVersion: "version-a"}
	value.TargetDigest = credentialref.ImportTargetDigest(value)
	return value
}

func credentialImportHTTPRequest(t *testing.T, input generated.CredentialImportRequest, body *countingBody, principal identity.Principal) *http.Request {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/credential-references/ref-a/import-stream", nil)
	request.Body = body
	request.ContentLength = -1
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Vsk-Credential-Request", base64.RawURLEncoding.EncodeToString(raw))
	return request.WithContext(identity.WithVerifiedPrincipal(request.Context(), principal))
}

func TestCredentialImportDeniesRemoteStaleAndJSONBeforeBodyRead(t *testing.T) {
	preflightCalls := 0
	service := credentialImportServiceStub{preflight: func(context.Context, generated.CredentialImportRequest, identity.Principal) (*generated.CredentialImportSubmission, error) {
		preflightCalls++
		return nil, failure.New(generated.ErrorCodePlanStale, "credential-import-revision", false)
	}, importer: func(context.Context, generated.CredentialImportRequest, []byte, identity.Principal) (generated.CredentialImportSubmission, error) {
		t.Fatal("import called")
		return generated.CredentialImportSubmission{}, nil
	}}
	app := credentialImportTestApp(t, service)
	for _, fixture := range []struct {
		name, method, contentType string
		principal                 identity.Principal
		size                      int
	}{
		{name: "remote", method: http.MethodPost, contentType: "application/octet-stream", principal: identity.Principal{ID: "human-a", Method: identity.CloudflareAccessMethod}, size: 24},
		{name: "json", method: http.MethodPost, contentType: "application/json", principal: identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}, size: 24},
		{name: "declared oversize", method: http.MethodPost, contentType: "application/octet-stream", principal: identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}, size: 4097},
		{name: "stale", method: http.MethodPost, contentType: "application/octet-stream", principal: identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}, size: 24},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			body := &countingBody{data: bytes.NewReader(bytes.Repeat([]byte("x"), fixture.size))}
			request := credentialImportHTTPRequest(t, credentialImportInput(), body, fixture.principal)
			request.Header.Set("Content-Type", fixture.contentType)
			if fixture.name == "declared oversize" {
				request.ContentLength = int64(fixture.size)
			}
			response := httptest.NewRecorder()
			app.ServeHTTP(response, request)
			if response.Code < 400 || body.reads != 0 || strings.Contains(response.Body.String(), "synthetic-private-canary") {
				t.Fatalf("status=%d reads=%d body=%s", response.Code, body.reads, response.Body.String())
			}
		})
	}
	if preflightCalls != 1 {
		t.Fatalf("preflight calls=%d", preflightCalls)
	}
	if RemoteReadRequestAllowed(http.MethodPost, "/api/v1/credential-references/ref-a/import-stream") || ConstrainedSSHRequestAllowed(http.MethodPost, "/api/v1/credential-references/ref-a/import-stream") {
		t.Fatal("remote credential import admitted")
	}
}

func TestCredentialImportReadsBoundedBodyOnlyAfterPreflight(t *testing.T) {
	body := &countingBody{data: bytes.NewReader([]byte("synthetic-private-canary"))}
	preflightCalls, importCalls := 0, 0
	service := credentialImportServiceStub{preflight: func(context.Context, generated.CredentialImportRequest, identity.Principal) (*generated.CredentialImportSubmission, error) {
		preflightCalls++
		if body.reads != 0 {
			t.Fatal("body read before preflight")
		}
		return nil, nil
	}, importer: func(_ context.Context, input generated.CredentialImportRequest, private []byte, principal identity.Principal) (generated.CredentialImportSubmission, error) {
		importCalls++
		if string(private) != "synthetic-private-canary" || principal.Method != identity.LocalOSPeerMethod {
			t.Fatal("private binding changed")
		}
		return generated.CredentialImportSubmission{Schema: generated.SchemaIDCredentialImportSubmission, SchemaVersion: "1.1.0", DraftID: "draft-a", ReferenceID: input.ReferenceID, CiphertextFingerprint: "sha256:" + strings.Repeat("b", 64), Status: "draft", StateRevision: 1, RecoveryEpoch: 0}, nil
	}}
	app := credentialImportTestApp(t, service)
	response := httptest.NewRecorder()
	app.ServeHTTP(response, credentialImportHTTPRequest(t, credentialImportInput(), body, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}))
	if response.Code != http.StatusOK || preflightCalls != 1 || importCalls != 1 || strings.Contains(response.Body.String(), "synthetic-private-canary") || strings.Contains(response.Body.String(), "ciphertext_name") {
		t.Fatalf("status=%d preflight=%d import=%d body=%s", response.Code, preflightCalls, importCalls, response.Body.String())
	}
}

func TestCredentialImportRejectsMalformedMetadataBeforeBodyRead(t *testing.T) {
	service := credentialImportServiceStub{preflight: func(context.Context, generated.CredentialImportRequest, identity.Principal) (*generated.CredentialImportSubmission, error) {
		t.Fatal("preflight called")
		return nil, nil
	}, importer: func(context.Context, generated.CredentialImportRequest, []byte, identity.Principal) (generated.CredentialImportSubmission, error) {
		t.Fatal("import called")
		return generated.CredentialImportSubmission{}, nil
	}}
	app := credentialImportTestApp(t, service)
	for _, fixture := range []struct {
		name  string
		alter func(*http.Request)
	}{
		{name: "duplicate header", alter: func(request *http.Request) { request.Header.Add("X-Vsk-Credential-Request", "duplicate") }},
		{name: "oversize header", alter: func(request *http.Request) { request.Header.Set("X-Vsk-Credential-Request", strings.Repeat("a", 5465)) }},
		{name: "caller fingerprint", alter: func(request *http.Request) {
			raw := []byte(`{"schema":"vegastack-labs.dev/credential-import-request","schemaVersion":"1.1.0","expectedStateRevision":0,"recoveryEpoch":0,"targetDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","idempotencyKey":"import-a","referenceId":"ref-a","consumerId":"consumer-a","purposeId":"purpose-a","targetId":"target-a","resolverId":"native-systemd","materialVersion":"version-a","fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`)
			request.Header.Set("X-Vsk-Credential-Request", base64.RawURLEncoding.EncodeToString(raw))
		}},
		{name: "path mismatch", alter: func(request *http.Request) { request.URL.Path = "/api/v1/credential-references/ref-b/import-stream" }},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			body := &countingBody{data: bytes.NewReader([]byte("synthetic-private-canary"))}
			request := credentialImportHTTPRequest(t, credentialImportInput(), body, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod})
			fixture.alter(request)
			response := httptest.NewRecorder()
			app.ServeHTTP(response, request)
			if response.Code < 400 || body.reads != 0 || strings.Contains(response.Body.String(), "synthetic-private-canary") {
				t.Fatalf("status=%d reads=%d body=%s", response.Code, body.reads, response.Body.String())
			}
		})
	}
}

func TestCredentialImportStreamingOverrunNeverReachesService(t *testing.T) {
	importCalls := 0
	service := credentialImportServiceStub{preflight: func(context.Context, generated.CredentialImportRequest, identity.Principal) (*generated.CredentialImportSubmission, error) {
		return nil, nil
	}, importer: func(context.Context, generated.CredentialImportRequest, []byte, identity.Principal) (generated.CredentialImportSubmission, error) {
		importCalls++
		return generated.CredentialImportSubmission{}, nil
	}}
	app := credentialImportTestApp(t, service)
	body := &countingBody{data: bytes.NewReader(bytes.Repeat([]byte("x"), 4097))}
	request := credentialImportHTTPRequest(t, credentialImportInput(), body, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod})
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code < 400 || body.reads == 0 || importCalls != 0 || strings.Contains(response.Body.String(), "synthetic-private-canary") {
		t.Fatalf("status=%d reads=%d imports=%d", response.Code, body.reads, importCalls)
	}
}

func TestCredentialImportExactRetryReturnsBeforeBodyRead(t *testing.T) {
	input := credentialImportInput()
	existing := generated.CredentialImportSubmission{Schema: generated.SchemaIDCredentialImportSubmission, SchemaVersion: "1.1.0", DraftID: "draft-a", ReferenceID: input.ReferenceID, CiphertextFingerprint: "sha256:" + strings.Repeat("b", 64), Status: "draft", StateRevision: 1, RecoveryEpoch: 0}
	service := credentialImportServiceStub{preflight: func(context.Context, generated.CredentialImportRequest, identity.Principal) (*generated.CredentialImportSubmission, error) {
		return &existing, nil
	}, importer: func(context.Context, generated.CredentialImportRequest, []byte, identity.Principal) (generated.CredentialImportSubmission, error) {
		t.Fatal("retry imported again")
		return generated.CredentialImportSubmission{}, nil
	}}
	app := credentialImportTestApp(t, service)
	body := &countingBody{data: bytes.NewReader([]byte("synthetic-private-canary"))}
	response := httptest.NewRecorder()
	app.ServeHTTP(response, credentialImportHTTPRequest(t, input, body, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}))
	if response.Code != http.StatusOK || body.reads != 0 || strings.Contains(response.Body.String(), "synthetic-private-canary") {
		t.Fatalf("status=%d reads=%d body=%s", response.Code, body.reads, response.Body.String())
	}
}
