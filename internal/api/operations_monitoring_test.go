package api

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOperationsAuthorizationPrecedesParsingOrCollection(t *testing.T) {
	for _, allow := range []bool{false, true} {
		calls := 0
		app, e := NewApplication(Config{Authority: testAuthority{}, Authorizer: authorizerFunc(func(context.Context, identity.Principal, authorization.ReadTarget) (authorization.ReadScope, error) {
			if !allow {
				return authorization.ReadScope{}, failure.New(generated.ErrorCodeAuthorizationDenied, "operations", false)
			}
			return authorization.ReadScope{}, nil
		}), Reads: testReads{}, Results: result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-test", nil }), Cursors: testCursor{}})
		if e != nil {
			t.Fatal(e)
		}
		fn := func(context.Context) (generated.OperationsStatusData, error) {
			calls++
			return generated.OperationsStatusData{Schema: generated.SchemaIDOperationsStatusData, SchemaVersion: "1.0.0", Alerts: []generated.OperationsAlert{}, Deliveries: []generated.OutboxRecordData{}, Notifications: "disabled"}, nil
		}
		if e = RegisterOperationsMonitoring(app, OperationsMonitoring{Status: fn, Observe: fn}); e != nil {
			t.Fatal(e)
		}
		for _, tc := range []struct {
			method, path, body string
			want               int
		}{{"GET", "/api/v1/operations", "", 200}, {"POST", "/api/v1/operations/observe", `{"schema":"vegastack-labs.dev/operations-observe-request","schemaVersion":"1.0.0"}`, 200}, {"POST", "/api/v1/operations/observe", `{"schema":"vegastack-labs.dev/operations-observe-request","schemaVersion":"1.0.0","state":"healthy","private-secret":"seed"}`, 400}} {
			before := calls
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			r = r.WithContext(identity.WithVerifiedPrincipal(r.Context(), identity.Principal{ID: "operator-a", Method: identity.LocalOSPeerMethod}))
			w := httptest.NewRecorder()
			app.ServeHTTP(w, r)
			want := tc.want
			if !allow {
				want = http.StatusForbidden
			}
			if w.Code != want {
				t.Fatal(allow, tc.method, w.Code, w.Body.String())
			}
			if (!allow || tc.want != 200) && calls != before {
				t.Fatal("denied/invalid request collected observations")
			}
			if strings.Contains(w.Body.String(), "private-secret") {
				t.Fatal("input leaked")
			}
		}
	}
}
