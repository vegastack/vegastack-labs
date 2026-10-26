// Package servicecatalog defines provider-neutral service registration intents.
package servicecatalog

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

const AdapterID = "core.service-import"
const Operation = "service.import"
const OperationID = "service-import"

type Policy struct {
	Definition        generated.ServiceDefinition
	ResourceKeyDigest string
}

func Digest(v any) string { return hostaction.Digest(v) }
func ValidateImportRequest(r generated.ServiceImportRequest) error {
	raw, err := json.Marshal(r)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDServiceImportRequest, raw, generated.ContractExact) != nil || r.ExpectedServiceRevision != 0 || r.ExpectedDeclarationRevision != 0 {
		return failure.New(generated.ErrorCodeInputInvalid, "service-import", false)
	}
	return nil
}

const DeploymentAdapterID = "core.service-deployment"
const DeploymentOperation = "service.deploy"
const DeploymentOperationID = "service-deployment"

type DeploymentPolicy struct {
	Binding   generated.ServiceDeploymentBinding
	Artifacts []generated.ServiceDeploymentArtifact
}
type DeploymentOutcome struct {
	ProviderReceiptID string
	ProviderStage     string
	Status            string
	ReceiptDigest     string
	RuntimeDigest     string
	RunningDigest     string
	Running           bool
	Healthy           bool
}

func ValidateDeploymentRequest(r generated.ServiceDeploymentRequest) error {
	raw, err := json.Marshal(r)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDServiceDeploymentRequest, raw, generated.ContractExact) != nil || r.Binding.ServiceID != r.Definition.ServiceID || r.Binding.BindingID != r.Definition.BindingID || r.Artifact.ManifestSHA != r.Artifact.Digest || r.ArtifactProofDigest != Digest(r.Artifact) {
		return failure.New(generated.ErrorCodeInputInvalid, "service-deployment", false)
	}
	return nil
}
