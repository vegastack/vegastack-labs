package store

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"testing"
	"time"
)

func deploymentRequestFixture() generated.ServiceDeploymentRequest {
	artifact := generated.ServiceDeploymentArtifact{Schema: generated.SchemaIDServiceDeploymentArtifact, SchemaVersion: "1.0.0", ArtifactID: "image-a", Repository: "registry.example.test/team/app", Digest: serviceTestDigest, ManifestSHA: serviceTestDigest, BundleSHA: serviceTestDigest, PolicySHA: serviceTestDigest}
	return generated.ServiceDeploymentRequest{Schema: generated.SchemaIDServiceDeploymentRequest, SchemaVersion: "1.0.0", Definition: servicePolicyFixture().Definition, Binding: generated.ServiceDeploymentBinding{Schema: generated.SchemaIDServiceDeploymentBinding, SchemaVersion: "1.0.0", ServiceID: "service-a", BindingID: "binding-a", ConfigurationDigest: serviceTestDigest, DataPolicy: "stateless"}, Artifact: artifact, ArtifactProofDigest: servicecatalog.Digest(artifact), Action: "deploy", IdempotencyKey: "deployment-a", ReasonDigest: serviceTestDigest}
}
func TestDeploymentRequiresActualRuntimeProof(t *testing.T) {
	request := deploymentRequestFixture()
	apply := ServiceDeploymentApply{PlanID: "plan-a", RunID: "run-a"}
	for _, out := range []servicecatalog.DeploymentOutcome{
		{Status: "succeeded", Running: true, Healthy: true, RunningDigest: request.Artifact.Digest},
		{Status: "succeeded", ReceiptDigest: serviceTestDigest, RuntimeDigest: serviceTestDigest, Running: true, Healthy: false, RunningDigest: request.Artifact.Digest},
		{Status: "succeeded", ReceiptDigest: serviceTestDigest, RuntimeDigest: serviceTestDigest, Running: true, Healthy: true, RunningDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	} {
		record, err := deploymentRecord(request, apply, out, time.Now())
		if err != nil || record.Status != "partial" {
			t.Fatalf("unsupported success: %+v %v", record, err)
		}
	}
	good := servicecatalog.DeploymentOutcome{Status: "succeeded", ReceiptDigest: serviceTestDigest, RuntimeDigest: serviceTestDigest, Running: true, Healthy: true, RunningDigest: request.Artifact.Digest}
	record, err := deploymentRecord(request, apply, good, time.Now())
	if err != nil || record.Status != "succeeded" {
		t.Fatal(record, err)
	}
}
func TestDeploymentPolicyFrozenAndExact(t *testing.T) {
	in := deploymentRequestFixture()
	policy := servicecatalog.DeploymentPolicy{Binding: in.Binding, Artifacts: []generated.ServiceDeploymentArtifact{in.Artifact}}
	input := []servicecatalog.DeploymentPolicy{policy}
	c, err := normalizeConfig(Config{ToolVersion: "test", BuildVersion: "test", ServiceDeploymentPolicies: input})
	if err != nil {
		t.Fatal(err)
	}
	input[0].Artifacts[0].Repository = "changed"
	if c.ServiceDeploymentPolicies[0].Artifacts[0].Repository != in.Artifact.Repository {
		t.Fatal("artifact catalog aliased")
	}
	if servicecatalog.ValidateDeploymentRequest(in) != nil {
		t.Fatal("valid request rejected")
	}
	in.Artifact.BundleSHA = servicecatalog.Digest("changed")
	if servicecatalog.ValidateDeploymentRequest(in) == nil {
		t.Fatal("unsealed artifact accepted")
	}
}
func TestDeploymentDeclarationCannotMixIntents(t *testing.T) {
	in := deploymentRequestFixture()
	digest := servicecatalog.Digest(in)
	d := generated.DeclarationRevision{ServiceDeployment: &in, DeclarationID: deploymentDeclarationID(in), DeclarationType: "service.deployment", Revision: 1, StateRevision: 1, Status: "draft", Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: servicecatalog.DeploymentOperationID, OperationType: servicecatalog.DeploymentOperation, AdapterID: servicecatalog.DeploymentAdapterID, TargetID: in.Definition.ServiceID, InputDigest: digest, ArtifactDigest: digest}}}
	if !ValidateServiceDeploymentDeclaration(d) {
		t.Fatal("exact deployment rejected")
	}
	d.ServiceImport = &generated.ServiceImportRequest{}
	if ValidateServiceDeploymentDeclaration(d) {
		t.Fatal("mixed import accepted")
	}
	d.ServiceImport = nil
	d.Operations[0].Idempotent = true
	if ValidateServiceDeploymentDeclaration(d) {
		t.Fatal("replayable deployment accepted")
	}
}
