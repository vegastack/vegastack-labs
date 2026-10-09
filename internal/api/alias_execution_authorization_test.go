package api

import (
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"net/http/httptest"
	"testing"
)

func TestAliasExecutionRequiresDestinationHostScope(t *testing.T) {
	for _, missingHost := range []bool{false, true} {
		p := apiRunPlan()
		p.AuthorizationBranch = "human"
		p.Risk = "infrastructure"
		claim := generated.HostAliasClaimRequest{Schema: generated.SchemaIDHostAliasClaimRequest, SchemaVersion: "1.0.0", HostID: "destination-host", HostIdentityDigest: hostaction.Digest("host"), AliasIDs: []string{"alias-a"}, ExpectedStateRevision: p.Binding.PriorStateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch, IdempotencyKey: "claim"}
		p.HostAliasClaim = &claim
		p.Operations = p.Operations[:1]
		p.Operations[0].AdapterID = hostreplacement.AdapterID
		p.Operations[0].OperationType = hostreplacement.AliasClaimOperation
		p.Operations[0].TargetID = p.DeclarationID
		p.Operations[0].InputDigest = hostaction.Digest(claim)
		p.Operations[0].ArtifactDigest = p.Operations[0].InputDigest
		snapshot := authorization.EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 1, StateRevision: p.Binding.StateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch}
		targets := []string{"alias-a"}
		if !missingHost {
			targets = append(targets, "destination-host")
		}
		for _, id := range targets {
			snapshot.Grants = append(snapshot.Grants, authorization.EffectiveGrant{Role: authorization.RoleInfrastructureAdmin, AllowedAction: authorization.ActionExecute, Capability: hostreplacement.AliasClaimOperation, ResourceKind: "execution-target", ResourceID: id, Branch: authorization.BranchHuman})
		}
		recorder := &authorizationRecorderStub{}
		app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: snapshot}), recorder)
		request := httptest.NewRequest("POST", "/api/v1/plans/"+p.PlanID+"/execute", nil)
		request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-maintainer", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
		_, err := app.authorizeRunPlan(request, p)
		if missingHost {
			if err == nil {
				t.Fatal("alias-only execution authorized ownership on host")
			}
		} else if err != nil || len(recorder.records) != 2 {
			t.Fatal("full exact target execution failed", err, recorder.records)
		}
	}
}
