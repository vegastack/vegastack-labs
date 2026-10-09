package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestGateRoutesStayOperatorOnlyAndHaveNoDirectSetter(t *testing.T) {
	for _, candidate := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/gates/profile-drafts"},
		{http.MethodPost, "/api/v1/gates/G-008/pass"},
		{http.MethodPost, "/api/v1/gates/profile-drafts/binding-a/bind"},
	} {
		if RemoteReadRequestAllowed(candidate.method, candidate.path) || ConstrainedSSHRequestAllowed(candidate.method, candidate.path) {
			t.Errorf("nonlocal gate write admitted: %s", candidate.path)
		}
	}
	if !RemoteReadRequestAllowed(http.MethodPost, "/api/v1/gates/G-008/evidence") || !RemoteReadRequestAllowed(http.MethodPost, "/api/v1/gates/G-008/check") {
		t.Fatal("bounded browser gate draft/check routes unavailable")
	}
	if !RemoteReadRequestAllowed(http.MethodGet, "/api/v1/gates") || !RemoteReadRequestAllowed(http.MethodGet, "/api/v1/gates/G-008") {
		t.Fatal("read-only gate projections unavailable")
	}
}

func TestGateAuthorDenialOccursBeforeBodyRead(t *testing.T) {
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "0.0.0-test", ReleaseBuildID: "build-test"}, func() (string, error) { return "request-gate-test", nil })
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: allowOperationAuthorizer(), Reads: testReads{}, Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	denied := &effectiveAuthorizationStub{decision: authorization.Decision{ReasonCode: authorization.ReasonGrantMissing}}
	app.effective = EffectiveAuthorizationConfig{Authorizer: denied, Recorder: denied, Clock: time.Now}
	if err := RegisterGateOperations(app, GateOperations{Gates: &store.GateRepository{}, Revisions: &store.PlanRepository{}, Declarations: &change.Service{}, Results: factory}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/gates/profile-drafts", "/api/v1/gates/G-008/evidence"} {
		body := &countingBody{data: bytes.NewReader([]byte(`{"privateCanary":"must-not-read"}`))}
		request := httptest.NewRequest(http.MethodPost, path, nil)
		request.Body = body
		request.Header.Set("Content-Type", "application/json")
		request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}))
		response := httptest.NewRecorder()
		app.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden || body.reads != 0 || strings.Contains(response.Body.String(), "privateCanary") {
			t.Errorf("%s: %d reads=%d body=%s", path, response.Code, body.reads, response.Body.String())
		}
	}
}

func TestUnknownGateProjectionFailsClosedWithoutAppliedScope(t *testing.T) {
	definition := generated.GeneratedGateDefinitions[7]
	evaluation := gateUnknown(definition, "site-a", "applied-profile-missing", time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC), 3)
	if evaluation.Outcome != "unknown" || evaluation.ReadyForInput || evaluation.EvidenceSource != "none" || evaluation.RecoveryEpoch != 3 {
		t.Fatalf("unsafe projection: %#v", evaluation)
	}
}

func TestUnboundGateProjectionKeepsSafeBlockersButNeverPasses(t *testing.T) {
	for _, caseItem := range []struct {
		name, sourceOutcome, sourceReason, expectedOutcome, expectedReason string
	}{
		{"fixture", "blocked", "evidence-fixture-or-legacy", "blocked", "evidence-fixture-or-legacy"},
		{"expired", "blocked", "evidence-expired", "blocked", "evidence-expired"},
		{"missing", "blocked", "evidence-missing", "blocked", "evidence-missing"},
		{"unbound revision", "blocked", "evidence-wrong-revision", "unknown", "subject-binding-unavailable"},
		{"unexpected pass", "passed", "proof-verified", "unknown", "subject-binding-unavailable"},
	} {
		t.Run(caseItem.name, func(t *testing.T) {
			current := generated.GateEvaluation{Outcome: caseItem.sourceOutcome, ReasonCode: caseItem.sourceReason, ReadyForInput: true}
			got := gateUnboundProjection(current, true, "applicable")
			if got.Outcome != caseItem.expectedOutcome || got.ReasonCode != caseItem.expectedReason || got.Outcome == "passed" {
				t.Fatalf("unbound result: %+v", got)
			}
		})
	}
	deferred := gateUnboundProjection(generated.GateEvaluation{Outcome: "not-applicable", ReasonCode: "deferred"}, false, "deferred")
	if deferred.Outcome != "not-applicable" || deferred.ReasonCode != "deferred" {
		t.Fatalf("deferred result: %+v", deferred)
	}
}

func TestGateSubjectQueryBoundedAndExact(t *testing.T) {
	for _, item := range []struct {
		raw, want string
		valid     bool
	}{
		{"", "scope", true}, {"subjectId=host-a", "host-a", true},
		{"subjectId=", "", false}, {"subjectId=a&subjectId=b", "", false},
		{"subjectId=a&extra=b", "", false}, {"subjectId=host%2Fa", "", false},
		{"subjectId=%zz", "", false}, {"subjectId=" + strings.Repeat("a", 129), "", false},
	} {
		got, err := gateSubjectQuery(item.raw)
		if (err == nil) != item.valid || got != item.want {
			t.Errorf("query %q: %q %v", item.raw, got, err)
		}
	}
}

func TestHostGateReadScopeDeniedBeforeSnapshot(t *testing.T) {
	for _, path := range []string{"/api/v1/gates?subjectId=host-denied", "/api/v1/gates/host.hardening-baseline?subjectId=host-denied", "/api/v1/gates/host.hardening-baseline/check"} {
		t.Run(path, func(t *testing.T) {
			recorder := &authorizationRecorderStub{}
			app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: authorization.EffectivePolicySnapshot{
				PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 1, StateRevision: 0, RecoveryEpoch: 0,
				Grants: []authorization.EffectiveGrant{{Role: authorization.RoleReader, AllowedAction: authorization.ActionRead, Capability: "host.read", ResourceKind: "host", ResourceID: "host-other", Branch: authorization.BranchHuman}},
			}}), recorder)
			// Empty repositories deliberately cannot resolve a subject. Denial must precede any read.
			if err := RegisterGateOperations(app, GateOperations{Gates: &store.GateRepository{}, Revisions: &store.PlanRepository{}, Declarations: &change.Service{}, Results: app.config.Results}); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, path, nil)
			if strings.HasSuffix(path, "/check") {
				def, ok := gateDefinition("host.hardening-baseline")
				if !ok {
					t.Fatal("host gate absent")
				}
				body, err := json.Marshal(generated.GateCheckRequest{Schema: generated.SchemaIDGateCheckRequest, SchemaVersion: "1.0.0", ExpectedStateRevision: 0, RecoveryEpoch: 0, TargetDigest: "sha256:" + strings.Repeat("a", 64), IdempotencyKey: "host-check", GateID: def.GateID, SubjectID: "host-denied", DefinitionVersion: def.DefinitionVersion})
				if err != nil {
					t.Fatal(err)
				}
				r = httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
			}
			r = r.WithContext(identity.WithVerifiedPrincipal(r.Context(), identity.Principal{ID: "human-a", Kind: identity.PrincipalHuman, Method: identity.LocalOSPeerMethod}))
			w := httptest.NewRecorder()
			app.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("wrong host read: %d %s", w.Code, w.Body.String())
			}
			if len(recorder.records) != 1 {
				t.Fatalf("expected exact host authorization, records=%d", len(recorder.records))
			}
			decision := recorder.records[0].Decision
			if decision.Target.Capability != "host.read" || decision.Target.ResourceKind != "host" || decision.Target.ResourceID != "host-denied" || decision.Allowed {
				t.Fatalf("wrong authorization target: %+v", decision)
			}
		})
	}
}
