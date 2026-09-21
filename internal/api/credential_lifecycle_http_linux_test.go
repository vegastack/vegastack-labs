//go:build linux

package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func (fixture *lifecyclePublicFixture) httpLifecycleApp(t *testing.T) *Application {
	t.Helper()
	requestNumber := 0
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) {
		requestNumber++
		return fmt.Sprintf("request-lifecycle-%d", requestNumber), nil
	})
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: allowOperationAuthorizer(), Reads: testReads{}, Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	effective := store.NewEffectiveAuthorizationRepository(fixture.authority)
	app.effective = EffectiveAuthorizationConfig{Authorizer: authorization.NewEvaluator(effective), Recorder: effective, Clock: fixture.clock}
	if err := RegisterCredentialLifecycleOperation(app, CredentialLifecycleOperations{Lifecycle: fixture.service, Results: factory}); err != nil {
		t.Fatal(err)
	}
	return app
}

func (fixture *lifecyclePublicFixture) lifecycleHTTPPost(t *testing.T, app *Application, principal identity.Principal, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/credential-lifecycle-drafts", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), principal))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	return response
}

func (fixture *lifecyclePublicFixture) lifecycleDurableCounts(t *testing.T) (int, int) {
	t.Helper()
	db, err := sql.Open("sqlite3", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var bindings, decisions int
	if err := db.QueryRow("SELECT COUNT(*) FROM credential_lifecycle_bindings").Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM authorization_decisions").Scan(&decisions); err != nil {
		t.Fatal(err)
	}
	return bindings, decisions
}

func TestLifecycleHTTPValidAndDeniedBodiesPreserveDurableState(t *testing.T) {
	for _, mode := range []string{"valid", "browser", "value", "ciphertextFingerprint", "unknown", "wrong-scope", "stale"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newLifecyclePublicFixture(t)
			imported := fixture.importDraft(t, "version-1")
			input := fixture.stageRequest(t, imported)
			principal := fixture.principal
			if mode == "browser" {
				principal.Method = identity.CloudflareAccessMethod
			}
			if mode == "wrong-scope" {
				principal.ID = "human-lifecycle"
			}
			if mode == "stale" {
				input.ExpectedStateRevision++
				input.TargetDigest = credentialref.LifecycleTargetDigest(input)
			}
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "value" || mode == "ciphertextFingerprint" || mode == "unknown" {
				field := mode
				if mode == "unknown" {
					field = "privateUnknown"
				}
				raw = append(raw[:len(raw)-1], []byte(`,"`+field+`":"private-canary"}`)...)
			}
			app := fixture.httpLifecycleApp(t)
			before, beforeDecisions := fixture.lifecycleDurableCounts(t)
			beforeRevision, err := fixture.revisions.CurrentRevision(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			response := fixture.lifecycleHTTPPost(t, app, principal, raw)
			after, afterDecisions := fixture.lifecycleDurableCounts(t)
			afterRevision, err := fixture.revisions.CurrentRevision(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(response.Body.Bytes(), []byte("private-canary")) || bytes.Contains(response.Body.Bytes(), []byte("ciphertextFingerprint")) {
				t.Fatal("HTTP response leaked private input")
			}
			if mode == "valid" {
				if response.Code < 200 || response.Code >= 300 || after != before+1 || afterRevision.StateRevision != beforeRevision.StateRevision+2 || afterDecisions <= beforeDecisions {
					t.Fatalf("valid HTTP lifecycle: status=%d bindings=%d→%d revision=%+v→%+v decisions=%d→%d body=%s", response.Code, before, after, beforeRevision, afterRevision, beforeDecisions, afterDecisions, response.Body.String())
				}
			} else {
				if response.Code < 400 || after != before || afterRevision != beforeRevision {
					t.Fatalf("denied HTTP lifecycle mutated durable state: mode=%s status=%d bindings=%d→%d revision=%+v→%+v body=%s", mode, response.Code, before, after, beforeRevision, afterRevision, response.Body.String())
				}
				if mode == "wrong-scope" && afterDecisions <= beforeDecisions {
					t.Fatal("wrong-scope authorization denial was not durably recorded")
				}
			}
		})
	}
}
