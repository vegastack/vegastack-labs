package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestNativeProducerLookupRequiresLocalRunAndHostRead(t *testing.T) {
	in := generated.NativeProducerLookupRequest{Schema: generated.SchemaIDNativeProducerLookupRequest, SchemaVersion: "1.0.0", ScopeDigest: hostaction.Digest("scope"), ScenarioID: "action-replay", HostID: "host-a", PlanID: "plan-a", PlanDigest: hostaction.Digest("plan"), RunID: "run-a", StepID: "step-a"}
	for _, kind := range []string{"valid", "missing-run", "missing-host", "foreign-run-grant", "foreign-host-grant", "browser", "supplied-lease", "bundle-upload"} {
		t.Run(kind, func(t *testing.T) {
			grants := []authorization.EffectiveGrant{{Role: authorization.RoleReader, AllowedAction: authorization.ActionRead, Capability: "run.read", ResourceKind: "run", ResourceID: in.RunID}, {Role: authorization.RoleReader, AllowedAction: authorization.ActionRead, Capability: "host.read", ResourceKind: "host", ResourceID: in.HostID}}
			switch kind {
			case "missing-run":
				grants = grants[1:]
			case "missing-host":
				grants = grants[:1]
			case "foreign-run-grant":
				grants[0].ResourceID = "other-run"
			case "foreign-host-grant":
				grants[1].ResourceID = "other-host"
			}
			app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: authorization.EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 1, Grants: grants}}), &authorizationRecorderStub{})
			service := &qualificationServiceTest{}
			if err := RegisterQualificationOperations(app, QualificationOperations{Service: service, Revisions: store.NewPlanRepository(nil), Declarations: &replacementAPIDeclarations{}, Results: app.config.Results}); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(in)
			if kind == "bundle-upload" {
				raw = append(raw[:len(raw)-1], []byte(`,"actionBundle":{}}`)...)
			}
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
					t.Fatalf("exact read did not reach actual prerequisite boundary: calls=%d status=%d", service.calls, w.Code)
				}
			} else if service.calls != 0 || w.Code < 400 {
				t.Fatalf("untrusted bundle read reached producer: calls=%d status=%d", service.calls, w.Code)
			}
		})
	}
}
