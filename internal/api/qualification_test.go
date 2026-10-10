package api

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
	"strings"
	"testing"
)

type qualificationServiceTest struct{ calls int }

func (s *qualificationServiceTest) LookupNativeProducerData(context.Context, generated.NativeProducerLookupRequest) (generated.NativeProducerLookupData, error) {
	s.calls++
	return generated.NativeProducerLookupData{}, apiFailure(generated.ErrorCodePrerequisiteBlocked, "fixture")
}
func (s *qualificationServiceTest) Inspect(context.Context, generated.QualificationInspectRequest) (generated.QualificationInspectData, error) {
	s.calls++
	return generated.QualificationInspectData{}, apiFailure(generated.ErrorCodePrerequisiteBlocked, "fixture")
}
func (s *qualificationServiceTest) CollectDraft(context.Context, generated.NativeCollectRequest, audit.Attribution) (store.GateDraft, []generated.ScenarioResult, error) {
	s.calls++
	return store.GateDraft{}, nil, apiFailure(generated.ErrorCodePrerequisiteBlocked, "fixture")
}
func TestNativeCollectorRejectsUploadAndRequiresExactLocalGrants(t *testing.T) {
	in := generated.NativeCollectRequest{Schema: generated.SchemaIDNativeCollectRequest, SchemaVersion: "1.0.0", ScopeDigest: hostaction.BytesDigest([]byte("scope")), Stage: "baseline", EvidenceID: "evidence-a", ProfileID: "profile-a", Producers: []generated.NativeProducerReference{{Schema: generated.SchemaIDNativeProducerReference, SchemaVersion: "1.0.0", ScenarioID: "baseline-access", HostID: "host-a", PlanID: "plan-a", PlanDigest: hostaction.BytesDigest([]byte("plan")), RunID: "run-a", StepID: "step-a", LeaseID: "lease-a"}}, ExpectedStateRevision: 1, RecoveryEpoch: 0, IdempotencyKey: "collect-a"}
	for _, kind := range []string{"valid", "missing-gate", "missing-declaration", "browser", "report", "host-valid", "host-missing-grant", "host-missing-id", "host-role-stage"} {
		t.Run(kind, func(t *testing.T) {
			grants := []authorization.EffectiveGrant{{Role: authorization.RoleInfrastructureAdmin, AllowedAction: authorization.ActionAuthor, Capability: "gate.evidence.author", ResourceKind: "gate", ResourceID: "native.baseline"}, {Role: authorization.RoleInfrastructureAdmin, AllowedAction: authorization.ActionAuthor, Capability: "declaration.author", ResourceKind: "declaration", ResourceID: "gate-evidence-evidence-a"}}
			if kind == "missing-gate" {
				grants = grants[1:]
			}
			if kind == "missing-declaration" {
				grants = grants[:1]
			}
			request := in
			if strings.HasPrefix(kind, "host-") {
				request.HostID, request.HostGateID = "host-a", "platform-safety"
				if kind != "host-missing-grant" {
					grants = append(grants, authorization.EffectiveGrant{Role: authorization.RoleInfrastructureAdmin, AllowedAction: authorization.ActionAuthor, Capability: "gate.evidence.author", ResourceKind: "gate", ResourceID: "platform-safety"})
				}
				if kind == "host-missing-id" {
					request.HostID = ""
				}
				if kind == "host-role-stage" {
					request.Stage = "role"
				}
			}
			app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: authorization.EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 1, Grants: grants}}), &authorizationRecorderStub{})
			service := &qualificationServiceTest{}
			if err := RegisterQualificationOperations(app, QualificationOperations{Service: service, Revisions: store.NewPlanRepository(nil), Declarations: &replacementAPIDeclarations{}, Results: app.config.Results}); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(request)
			if kind == "report" {
				raw = append(raw[:len(raw)-1], []byte(`,"report":{"passed":true}}`)...)
			}
			method := identity.LocalOSPeerMethod
			if kind == "browser" {
				method = "slack"
			}
			w := replacementAPICall(app, http.MethodPost, "/api/v1/qualification/collect", string(raw), method)
			if kind == "valid" || kind == "host-valid" {
				if service.calls != 1 || w.Code != 412 {
					t.Fatalf("valid scope did not reach real prerequisite boundary: %d calls=%d %s", w.Code, service.calls, w.Body)
				}
			} else if service.calls != 0 || w.Code < 400 {
				t.Fatalf("untrusted collection reached producer: %d calls=%d", w.Code, service.calls)
			}
		})
	}
}
