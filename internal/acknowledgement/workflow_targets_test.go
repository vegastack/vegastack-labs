package acknowledgement

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"testing"
)

func TestAliasAcknowledgementRequiresDestinationHostScope(t *testing.T) {
	for _, missingHost := range []bool{false, true} {
		service, repo, p := newService(t)
		claim := generated.HostAliasClaimRequest{Schema: generated.SchemaIDHostAliasClaimRequest, SchemaVersion: "1.0.0", HostID: "destination-host", HostIdentityDigest: testDigest, AliasIDs: []string{"alias-a"}, ExpectedStateRevision: p.Binding.PriorStateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch, IdempotencyKey: "claim"}
		p.HostAliasClaim = &claim
		p.Operations[0].AdapterID = hostreplacement.AdapterID
		p.Operations[0].OperationType = hostreplacement.AliasClaimOperation
		p.Operations[0].TargetID = p.DeclarationID
		p.Operations[0].InputDigest = hostaction.Digest(claim)
		p.Operations[0].ArtifactDigest = p.Operations[0].InputDigest
		service.config.Plans = fixedPlanReader{plan: p}
		auth := &aliasTargetAuthorizer{missingHost: missingHost}
		service.config.Authorizer = auth
		_, err := service.Request(context.Background(), requestScope(), p.PlanID)
		if missingHost {
			if errorCode(err) != generated.ErrorCodeAuthorizationDenied || repo.created != 0 {
				t.Fatal("alias-only human approved host ownership mutation", err, repo.created)
			}
		} else if err != nil || !auth.host || !auth.alias {
			t.Fatal("full scope did not acknowledge all affected resources", err, auth)
		}
	}
}

type aliasTargetAuthorizer struct{ missingHost, host, alias bool }

func (a *aliasTargetAuthorizer) Authorize(ctx context.Context, p identity.Principal, r authorization.Request) (authorization.Decision, error) {
	if r.Target.ResourceID == "destination-host" {
		a.host = true
		if a.missingHost {
			return denyAuthorizer{}.Authorize(ctx, p, r)
		}
	}
	if r.Target.ResourceID == "alias-a" {
		a.alias = true
	}
	return allowAuthorizer{}.Authorize(ctx, p, r)
}
