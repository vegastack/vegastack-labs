package api

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type lifecycleServiceFunc func(context.Context, generated.CredentialLifecycleRequest, identity.Principal) (generated.CredentialLifecycleSubmission, error)

func (service lifecycleServiceFunc) CreateDraft(ctx context.Context, input generated.CredentialLifecycleRequest, principal identity.Principal) (generated.CredentialLifecycleSubmission, error) {
	return service(ctx, input, principal)
}

func TestLifecycleEndpointRejectsBrowserPrivateAndFingerprintFields(t *testing.T) {
	calls := 0
	app := credentialImportTestApp(t, credentialImportServiceStub{})
	service := lifecycleServiceFunc(func(context.Context, generated.CredentialLifecycleRequest, identity.Principal) (generated.CredentialLifecycleSubmission, error) {
		calls++
		return generated.CredentialLifecycleSubmission{}, nil
	})
	if err := RegisterCredentialLifecycleOperation(app, CredentialLifecycleOperations{Lifecycle: service, Results: app.config.Results}); err != nil {
		t.Fatal(err)
	}
	draft := "draft-a"
	input := generated.CredentialLifecycleRequest{Schema: generated.SchemaIDCredentialLifecycleRequest, SchemaVersion: "1.3.0", Action: "credential.stage", DraftID: &draft, ReferenceID: "reference-a", ConsumerIDs: []string{"consumer-a"}, RequiredDeniedConsumerIDs: []string{}, MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "target-a", ExpectedStateRevision: 1, RecoveryEpoch: 0, IdempotencyKey: "key-a"}
	input.TargetDigest = credentialref.LifecycleTargetDigest(input)
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"browser", "value", "ciphertextFingerprint", "acknowledgement"} {
		t.Run(mode, func(t *testing.T) {
			raw := append([]byte(nil), encoded...)
			principal := identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}
			if mode == "browser" {
				principal.Method = identity.CloudflareAccessMethod
			} else {
				raw = append(raw[:len(raw)-1], []byte(",\""+mode+"\":\"private-canary\"}")...)
			}
			body := &countingBody{data: bytes.NewReader(raw)}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/credential-lifecycle-drafts", nil)
			request.Body = body
			request.ContentLength = -1
			request.Header.Set("Content-Type", "application/json")
			request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), principal))
			response := httptest.NewRecorder()
			app.ServeHTTP(response, request)
			if response.Code < 400 || calls != 0 || strings.Contains(response.Body.String(), "private-canary") {
				t.Fatalf("unsafe endpoint: status=%d calls=%d response=%s", response.Code, calls, response.Body.String())
			}
			if mode == "browser" && body.reads != 0 {
				t.Fatal("browser denial read private body")
			}
		})
	}
	if RemoteReadRequestAllowed(http.MethodPost, "/api/v1/credential-lifecycle-drafts") {
		t.Fatal("browser admission widened to lifecycle authoring")
	}
}
