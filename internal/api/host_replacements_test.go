package api

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func replacementAPIInput() generated.HostReplacementRequest {
	d := func(s string) string { return hostaction.BytesDigest([]byte(s)) }
	return generated.HostReplacementRequest{
		Schema: generated.SchemaIDHostReplacementRequest, SchemaVersion: "1.0.0", ReplacementID: "replacement-a", Operation: "freeze", RestorationClass: "stateless-role",
		OldHostID: "old-host", NewHostID: "new-host", OldIdentityDigest: d("old"), NewIdentityDigest: d("new"), OldTargetDigest: d("old-target"), NewTargetDigest: d("new-target"), OldSSHHostKeyDigest: d("old-key"), NewSSHHostKeyDigest: d("new-key"), OldTargetRevision: 1, NewTargetRevision: 1,
		ProfileID: "profile", ProfileLockDigest: d("profile"), OldRoleBindingDigest: d("old-role"), RoleDeclarationID: "old-role", RoleDeclarationRevision: 1, ProposedRoleDeclarationID: "new-role", ProposedRoleDeclarationRevision: 1, ProposedRoleBindingDigest: d("new-role"), PreservedPreimageDigest: d("preimage"),
		AliasBindings: []generated.HostReplacementAliasBinding{{Schema: generated.SchemaIDHostReplacementAliasBinding, SchemaVersion: "1.0.0", AliasID: "alias-a", OwnerHostID: "old-host", OwnerIdentityDigest: d("old"), OwnerRevision: 1, OwnershipGeneration: 1}}, PayloadIDs: []string{}, VolumeIDs: []string{}, ResourceIDs: []string{},
		OSPreparation: generated.HostReplacementOsPreparation{Schema: generated.SchemaIDHostReplacementOsPreparation, SchemaVersion: "1.0.0", Method: "administrator-prepared", ObservationID: "observation-a", ObservationDigest: d("observation"), HostIdentityDigest: d("new"), ConfirmedAt: "2026-10-09T12:00:00Z"}, ExpectedStateRevision: 1, RecoveryEpoch: 0, IdempotencyKey: "freeze-a",
	}
}

type replacementAPIRepository struct {
	stages int
	input  generated.HostReplacementRequest
}

func (f *replacementAPIRepository) Stage(_ context.Context, in generated.HostReplacementRequest, _ audit.Attribution) (store.HostReplacementDraft, error) {
	f.stages++
	f.input = in
	d := hostaction.Digest(in)
	return store.HostReplacementDraft{ID: "host-replacement-" + d[7:39], Digest: d, Request: in}, nil
}
func (f *replacementAPIRepository) Get(context.Context, string) (generated.HostReplacementState, error) {
	return generated.HostReplacementState{ReplacementID: "replacement-a", OldHostID: "old-host", NewHostID: "new-host", BindingDigest: "private-canary"}, nil
}

type replacementAPIDeclarations struct {
	calls   int
	request generated.DeclarationRevisionRequest
}

func (f *replacementAPIDeclarations) Revise(_ context.Context, _ change.AuthorScope, r generated.DeclarationRevisionRequest) (change.Result, error) {
	f.calls++
	f.request = r
	return change.Result{Document: generated.DeclarationRevision{StateRevision: r.ExpectedStateRevision + 1, RecoveryEpoch: r.RecoveryEpoch}}, nil
}
func (*replacementAPIDeclarations) Get(context.Context, string, int64) (generated.DeclarationRevision, error) {
	return generated.DeclarationRevision{}, nil
}
func replacementAPICall(app *Application, method, path, body, authMethod string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if authMethod != "" {
		r = r.WithContext(identity.WithVerifiedPrincipal(r.Context(), identity.Principal{ID: "human-a", Method: authMethod, Kind: identity.PrincipalHuman}))
	}
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	return w
}
func replacementAPIApp(t *testing.T, grants []authorization.EffectiveGrant) (*Application, *replacementAPIRepository, *replacementAPIDeclarations) {
	t.Helper()
	app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: authorization.EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 1, Grants: grants}}), &authorizationRecorderStub{})
	repo := &replacementAPIRepository{}
	decl := &replacementAPIDeclarations{}
	if err := RegisterHostReplacementOperations(app, HostReplacementOperations{Replacements: repo, Declarations: decl, Results: app.config.Results}); err != nil {
		t.Fatal(err)
	}
	return app, repo, decl
}
func replacementAPIGrants(in generated.HostReplacementRequest) []authorization.EffectiveGrant {
	d := hostaction.Digest(in)
	return []authorization.EffectiveGrant{
		{Role: authorization.RoleInfrastructureAdmin, AllowedAction: authorization.ActionAuthor, Capability: "host.replacement.prepare", ResourceKind: "host", ResourceID: in.OldHostID},
		{Role: authorization.RoleInfrastructureAdmin, AllowedAction: authorization.ActionAuthor, Capability: "host.replacement.prepare", ResourceKind: "host", ResourceID: in.NewHostID},
		{Role: authorization.RoleInfrastructureAdmin, AllowedAction: authorization.ActionAuthor, Capability: "declaration.author", ResourceKind: "declaration", ResourceID: "host-replacement-" + d[7:39]},
	}
}
func TestReplacementAPIRequiresBothSubjectsAndExactAuthorGrant(t *testing.T) {
	for _, method := range []string{identity.LocalOSPeerMethod, identity.CloudflareAccessMethod} {
		for _, operation := range []string{"freeze", "commit"} {
			in := replacementAPIInput()
			in.Operation = operation
			raw, _ := json.Marshal(in)
			for _, missing := range []int{-1, 0, 1, 2} {
				grants := replacementAPIGrants(in)
				if missing >= 0 {
					grants = append(grants[:missing], grants[missing+1:]...)
				}
				app, repo, decl := replacementAPIApp(t, grants)
				w := replacementAPICall(app, "POST", "/api/v1/host-replacements", string(raw), method)
				if missing >= 0 {
					if w.Code != http.StatusForbidden || repo.stages != 0 || decl.calls != 0 {
						t.Fatalf("missing grant%d status%d stages%d", missing, w.Code, repo.stages)
					}
					continue
				}
				if w.Code != http.StatusOK || repo.stages != 1 || decl.calls != 1 {
					t.Fatalf("good draft %d %s", w.Code, w.Body.String())
				}
				op := decl.request.Operations[0]
				if op.OperationType != "host.replacement."+operation || op.AdapterID != hostreplacement.AdapterID || op.TargetID != decl.request.DeclarationID || !op.Idempotent || op.InputDigest != hostaction.Digest(in) || len(decl.request.Extensions) != 1 {
					t.Fatal("draft widened operation")
				}
			}
		}
	}
}
func TestReplacementAPIRejectsMalformedAndUnscopedRead(t *testing.T) {
	in := replacementAPIInput()
	raw, _ := json.Marshal(in)
	good := string(raw)
	for _, tc := range []struct {
		body, method string
		status       int
	}{{good, identity.SlackSocketModeMethod, 403}, {strings.TrimSuffix(good, "}") + `,"reset":true}`, identity.LocalOSPeerMethod, 400}, {strings.Replace(good, `"osPreparation":{`, `"osPreparation":{"reset":true,`, 1), identity.LocalOSPeerMethod, 400}, {strings.Repeat(" ", hostreplacement.MaximumInput+1), identity.LocalOSPeerMethod, 400}, {good, "", 401}} {
		app, repo, _ := replacementAPIApp(t, replacementAPIGrants(in))
		w := replacementAPICall(app, "POST", "/api/v1/host-replacements", tc.body, tc.method)
		if w.Code != tc.status || repo.stages != 0 {
			t.Fatalf("denial status%d want%d body%s", w.Code, tc.status, w.Body.String())
		}
	}
	for _, which := range []string{"old-host", "new-host"} {
		app, _, _ := replacementAPIApp(t, []authorization.EffectiveGrant{{Role: authorization.RoleReader, AllowedAction: authorization.ActionRead, Capability: "host.read", ResourceKind: "host", ResourceID: which}})
		w := replacementAPICall(app, "GET", "/api/v1/host-replacements/replacement-a", "", identity.LocalOSPeerMethod)
		if w.Code != 403 || strings.Contains(w.Body.String(), "private-canary") {
			t.Fatal("partial host scope exposed replacement")
		}
	}
}
func TestDeclarationAPIAliasPayloadIsOperatorLocalOnly(t *testing.T) {
	c := generated.HostAliasClaimRequest{Schema: generated.SchemaIDHostAliasClaimRequest, SchemaVersion: "1.0.0", HostID: "host-a", HostIdentityDigest: hostaction.BytesDigest([]byte("host")), AliasIDs: []string{"alias-a"}, IdempotencyKey: "claim"}
	d := hostaction.Digest(c)
	in := generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: "claim-a", DeclarationType: "host.alias-claim", ExpectedRevision: 1, HostAliasClaim: &c, ReasonDigest: d, Extensions: []generated.ContractExtension{{Name: hostreplacement.AliasClaimExtension, ValueDigest: d}}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "claim", OperationType: hostreplacement.AliasClaimOperation, AdapterID: hostreplacement.AdapterID, TargetID: "claim-a", InputDigest: d, ArtifactDigest: d, Idempotent: true}}}
	raw, _ := json.Marshal(in)
	for _, method := range []string{identity.LocalOSPeerMethod, identity.CloudflareAccessMethod} {
		app, _, decl := replacementAPIApp(t, []authorization.EffectiveGrant{{Role: authorization.RoleInfrastructureAdmin, AllowedAction: authorization.ActionAuthor, Capability: "declaration.author", ResourceKind: "declaration", ResourceID: "claim-a"}})
		app.routes = append(app.routes, route{id: "api.v1.declarations.revise", method: "POST", pattern: "/api/v1/declarations/{declarationId}/revisions", deferredAuthorization: true, handler: app.reviseDeclaration(DeclarationPlanConfig{Declarations: decl, Results: app.config.Results, MaxBodyBytes: 32768})})
		w := replacementAPICall(app, "POST", "/api/v1/declarations/claim-a/revisions", string(raw), method)
		if method == identity.LocalOSPeerMethod {
			if w.Code != 200 || decl.request.HostAliasClaim == nil {
				t.Fatalf("typed local claim lost status%d %s", w.Code, w.Body.String())
			}
		} else if w.Code != 403 || decl.calls != 0 {
			t.Fatal("browser authored alias claim")
		}
	}
}
