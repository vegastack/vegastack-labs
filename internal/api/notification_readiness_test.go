package api

import (
	"bytes"
	"context"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNotificationReadinessAuthorizesBeforeBodyAndRejectsUploadedProof(t *testing.T) {
	for _, allow := range []bool{false, true} {
		effective := &effectiveAuthorizationStub{}
		if !allow {
			effective.decision.ReasonCode = authorization.ReasonGrantMissing
		}
		app := newAuthorizationTestApplication(t, effective, effective)
		calls := 0
		empty := func(context.Context) (generated.OperationsStatusData, error) {
			return generated.OperationsStatusData{}, nil
		}
		e := RegisterOperationsMonitoring(app, OperationsMonitoring{Status: empty, Observe: empty, Readiness: func(context.Context, generated.NotificationReadinessRequest) (generated.DeclarationRevision, error) {
			calls++
			return generated.DeclarationRevision{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "unselected-test-policy", false)
		}})
		if e != nil {
			t.Fatal(e)
		}
		for _, payload := range []string{`{"schema":"vegastack-labs.dev/notification-readiness-request","schemaVersion":"1.0.0","action":"canary-draft","requestId":"test-a","expectedStateRevision":0,"recoveryEpoch":0}`, `{"schema":"vegastack-labs.dev/notification-readiness-request","schemaVersion":"1.0.0","action":"evidence-draft","requestId":"test-a","expectedStateRevision":0,"recoveryEpoch":0,"passed":true,"webhook":"private-seed"}`} {
			before := calls
			body := &countingBody{data: bytes.NewReader([]byte(payload))}
			r := httptest.NewRequest(http.MethodPost, "/api/v1/operations/notification-readiness", nil)
			r.Body = body
			r.ContentLength = int64(len(payload))
			r.Header.Set("Content-Type", "application/json")
			r = r.WithContext(identity.WithVerifiedPrincipal(r.Context(), identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}))
			w := httptest.NewRecorder()
			app.ServeHTTP(w, r)
			if !allow && (w.Code != http.StatusForbidden || body.reads != 0 || calls != before) {
				t.Fatal("denied request read or prepared", w.Code, body.reads, calls)
			}
			if allow && strings.Contains(payload, "passed") && (w.Code != http.StatusBadRequest || calls != before) {
				t.Fatal("uploaded proof or target accepted", w.Code, w.Body.String())
			}
			if allow && !strings.Contains(payload, "passed") && calls != before+1 {
				t.Fatal("valid inert request did not reach preparer", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "private-seed") {
				t.Fatal("secret input leaked")
			}
		}
	}
}
