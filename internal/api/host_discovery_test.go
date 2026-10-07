package api

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type discoveryAPISpy struct{ calls int }

func (s *discoveryAPISpy) Begin(context.Context, hostdiscovery.BeginRequest) (hostdiscovery.Attempt, error) {
	s.calls++
	return hostdiscovery.Attempt{}, hostdiscovery.Error(generated.ErrorCodePrerequisiteBlocked)
}
func (s *discoveryAPISpy) Complete(context.Context, hostdiscovery.CompleteRequest) (generated.HostObservation, error) {
	s.calls++
	return generated.HostObservation{}, nil
}
func (s *discoveryAPISpy) Get(context.Context, string) (generated.HostObservation, error) {
	s.calls++
	return generated.HostObservation{}, nil
}
func (s *discoveryAPISpy) Fail(context.Context, hostdiscovery.Attempt, string, audit.Attribution) error {
	s.calls++
	return nil
}
func (s *discoveryAPISpy) Collect(context.Context, hostdiscovery.Target) (hostdiscovery.Collection, error) {
	s.calls++
	return hostdiscovery.Collection{}, nil
}
func TestDiscoveryAPIBoundsAndExactTargetAuthorization(t *testing.T) {
	recorder := &authorizationRecorderStub{}
	app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: authorization.EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 1, Grants: []authorization.EffectiveGrant{{Role: authorization.RoleInfrastructureAdmin, AllowedAction: authorization.ActionRead, Capability: "host.discovery.collect", ResourceKind: "host-discovery-target", ResourceID: "candidate-a"}}}}), recorder)
	spy := &discoveryAPISpy{}
	if err := RegisterHostDiscoveryOperations(app, HostDiscoveryOperations{Service: &hostdiscovery.Service{Repository: spy, Collector: spy}, Targets: store.NewHostDiscoveryRepository(nil), Declarations: &change.Service{}, Results: app.config.Results}); err != nil {
		t.Fatal(err)
	}
	good := `{"schema":"vegastack-labs.dev/host-discovery-request","schemaVersion":"1.0.0","targetId":"candidate-a","targetRevision":1,"expectedStateRevision":0,"recoveryEpoch":0,"idempotencyKey":"scan-a"}`
	for _, tc := range []struct {
		name, body    string
		authenticated bool
		status        int
	}{
		{"authentication", good, false, http.StatusUnauthorized},
		{"unknown", strings.TrimSuffix(good, "}") + `,"address":"private-canary"}`, true, http.StatusBadRequest},
		{"duplicate", strings.TrimSuffix(good, "}") + `,"targetId":"candidate-a"}`, true, http.StatusBadRequest},
		{"oversized", strings.Repeat(" ", 16385) + good, true, http.StatusBadRequest},
		{"wrong-target", strings.ReplaceAll(good, "candidate-a", "candidate-b"), true, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/host-observations", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			if tc.authenticated {
				r = r.WithContext(identity.WithVerifiedPrincipal(r.Context(), identity.Principal{ID: "operator-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
			}
			w := httptest.NewRecorder()
			app.ServeHTTP(w, r)
			if w.Code != tc.status || spy.calls != 0 || strings.Contains(w.Body.String(), "private-canary") {
				t.Fatalf("status=%d calls=%d body=%s", w.Code, spy.calls, w.Body.String())
			}
		})
	}
	if len(recorder.records) == 0 {
		t.Fatal("target denial not audited")
	}
}
