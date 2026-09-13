package authorization

import (
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func TestBindExternalExecutorIdentityRejectsPrincipalAndEvidenceWidening(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	other := "sha256:" + strings.Repeat("b", 64)
	executorID := "executor-ci"
	plan := generated.Plan{ExecutorMode: "external", ExecutorID: &executorID, Binding: generated.PlanBinding{RecoveryEpoch: 7}, Extensions: []generated.ContractExtension{{Name: "x-executor-project", ValueDigest: digest}, {Name: "x-executor-workflow", ValueDigest: digest}, {Name: "x-executor-ref", ValueDigest: digest}}}
	step := generated.RunStep{ExecutorID: executorID, AdapterID: "adapter-deploy"}
	request := generated.ExecutorClaimRequest{ExecutorID: executorID, PrincipalID: executorID, AdapterID: step.AdapterID, RecoveryEpoch: 7, Extensions: append([]generated.ContractExtension(nil), plan.Extensions...)}
	principal := identity.Principal{ID: executorID, Method: identity.CloudflareAccessMethod, Kind: identity.PrincipalPolicy}

	bound, ok := BindExternalExecutorIdentity(principal, request, plan, step)
	if !ok || bound.PrincipalID != executorID || bound.Project != digest || bound.Workflow != digest || bound.Ref != digest {
		t.Fatalf("bound = %#v, ok=%v", bound, ok)
	}

	wrongPrincipal := principal
	wrongPrincipal.ID = "executor-other"
	if _, ok := BindExternalExecutorIdentity(wrongPrincipal, request, plan, step); ok {
		t.Fatal("wrong authenticated principal was accepted")
	}
	widened := request
	widened.Extensions = append([]generated.ContractExtension(nil), request.Extensions...)
	widened.Extensions[2].ValueDigest = other
	if _, ok := BindExternalExecutorIdentity(principal, widened, plan, step); ok {
		t.Fatal("widened ref evidence was accepted")
	}
	unknown := request
	unknown.Extensions = append(unknown.Extensions, generated.ContractExtension{Name: "x-executor-unknown", ValueDigest: digest})
	if _, ok := BindExternalExecutorIdentity(principal, unknown, plan, step); ok {
		t.Fatal("unknown claim evidence was accepted")
	}
}
