package api

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
	"testing"
)

func TestNativeProducerLookupRequiresLocalRunAndHostRead(t *testing.T) {
	in := generated.NativeProducerLookupRequest{Schema: generated.SchemaIDNativeProducerLookupRequest, SchemaVersion: "1.0.0", ScopeDigest: hostaction.Digest("scope"), ScenarioID: "baseline-access", HostID: "host-a", PlanID: "plan-a", PlanDigest: hostaction.Digest("plan"), RunID: "run-a", StepID: "step-a", RecoveryEpoch: 0}
	for _, kind := range []string{"valid", "missing-run", "missing-host", "browser", "supplied-lease"} {
		t.Run(kind, func(t *testing.T) {
			grants := []authorization.EffectiveGrant{{Role: authorization.RoleReader, AllowedAction: authorization.ActionRead, Capability: "run.read", ResourceKind: "run", ResourceID: in.RunID}, {Role: authorization.RoleReader, AllowedAction: authorization.ActionRead, Capability: "host.read", ResourceKind: "host", ResourceID: in.HostID}}
			if kind == "missing-run" {
				grants = grants[1:]
			}
			if kind == "missing-host" {
				grants = grants[:1]
			}
			app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: authorization.EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 1, Grants: grants}}), &authorizationRecorderStub{})
			service := &qualificationServiceTest{}
			if err := RegisterQualificationOperations(app, QualificationOperations{Service: service, Revisions: store.NewPlanRepository(nil), Declarations: &replacementAPIDeclarations{}, Results: app.config.Results}); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(in)
			if kind == "supplied-lease" {
				raw = append(raw[:len(raw)-1], []byte(`,"leaseId":"caller-lease"}`)...)
			}
			method := identity.LocalOSPeerMethod
			if kind == "browser" {
				method = "slack"
			}
			w := replacementAPICall(app, http.MethodPost, "/api/v1/qualification/native/producer", string(raw), method)
			if kind == "valid" {
				if service.calls != 1 || w.Code != 412 {
					t.Fatalf("expected protected service boundary, code=%d calls=%d", w.Code, service.calls)
				}
			} else if service.calls != 0 || w.Code < 400 {
				t.Fatalf("lookup escaped authorization: code=%d calls=%d", w.Code, service.calls)
			}
		})
	}
}
