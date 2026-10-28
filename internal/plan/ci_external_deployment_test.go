package plan

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
)

type ciCompanionRepositoryFixture struct {
	fakePlanRepository
	policy  store.CIExternalDeploymentPolicy
	commits []store.CICompanionCommit
}

func (f *ciCompanionRepositoryFixture) ExternalDeploymentPolicy(string) (store.CIExternalDeploymentPolicy, error) {
	return f.policy, nil
}
func (f *ciCompanionRepositoryFixture) CommitCICompanion(_ context.Context, q store.CICompanionCommit) (store.PlanCommitResult, error) {
	f.commits = append(f.commits, q)
	return store.PlanCommitResult{Plan: q.Plan}, nil
}
func TestCICompanionPreservesParentRevisionAndSealsOnlyExactApplication(t *testing.T) {
	parent := createWithDeclaration(t, validDeclaration())
	policy := store.CIExternalDeploymentPolicy{Binding: generated.CiExternalDeploymentBinding{BindingID: "external-one", ExecutionBindingID: "ci-one", ExecutorID: "automation-one", ServiceID: "service-one", ArtifactID: "image-one", MaterialVersion: "version-one", ResolverID: "resolver-one"}, Definition: generated.ServiceDefinition{ServiceID: "service-one"}, Artifact: generated.ServiceDeploymentArtifact{ArtifactID: "image-one", Repository: "registry.example/app", Digest: hostaction.Digest("image")}, ReferenceID: "app-one", ResolverID: "resolver-one"}
	parent.Plan.CIJob = &generated.CiJobRequest{ExecutionBindingID: "ci-one", DeploymentDigest: policy.Digest()}
	manifest := hostaction.Digest("parent-transport-manifest")
	parent.Plan.Extensions = []generated.ContractExtension{{Name: "x-credential-bindings", ValueDigest: manifest}}
	repo := &ciCompanionRepositoryFixture{policy: policy}
	service := &Service{config: Config{Repository: repo}}
	original, _ := json.Marshal(parent.Plan)
	for i := 0; i < 2; i++ {
		out, e := service.ensureCICompanion(context.Background(), parent, AuthorScope{PrincipalID: "operator-one", PrincipalMethod: "local-os-peer"})
		if e != nil {
			t.Fatal(e)
		}
		if out.CompanionPlanID == "" || out.Plan.PlanID != parent.Plan.PlanID {
			t.Fatal("navigation or parent changed")
		}
	}
	if len(repo.commits) != 2 || repo.commits[0].Plan.PlanDigest != repo.commits[1].Plan.PlanDigest {
		t.Fatal("companion nondeterministic")
	}
	child := repo.commits[0].Plan
	raw, _ := json.Marshal(child)
	if e := generated.ValidateContractJSON(generated.SchemaIDPlan, raw, generated.ContractExact); e != nil {
		t.Fatal(e)
	}
	binding := parent.Plan.Binding
	binding.TargetDigest = hostaction.Digest([]string{"service-one"})
	if child.Binding != binding || child.CIJob != nil || child.ExecutorMode != "external" || child.AuthorizationBranch != "human" || child.Risk != "production-like" || len(child.Operations) != 1 {
		t.Fatal("revision or executor changed")
	}
	credential := policy.Credential(child.Binding.StateRevision, child.Binding.RecoveryEpoch)
	op := child.Operations[0]
	if op.TargetID != "service-one" || op.ArtifactDigest != policy.Artifact.Digest || op.InputDigest != credentialref.OperationManifestDigest([]credentialref.StepBinding{credential}, op.OperationID) {
		t.Fatal("application credential not exact")
	}
	after, _ := json.Marshal(parent.Plan)
	if string(after) != string(original) {
		t.Fatal("parent mutated")
	}
	repo.policy.Binding.MaterialVersion = "version-two"
	if _, e := service.ensureCICompanion(context.Background(), parent, AuthorScope{PrincipalID: "operator-one", PrincipalMethod: "local-os-peer"}); e == nil {
		t.Fatal("stale material profile accepted")
	}
}
