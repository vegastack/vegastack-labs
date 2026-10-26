package metadata

const serviceDeploymentRequestID = "vegastack-labs.dev/service-deployment-request"

func serviceDeploymentSchemas() []SchemaDefinition {
	ref := func(n, g, id string) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueObject, Required: true, Ref: id}
	}
	text := func(n, g string) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(1024)}
	}
	boolean := func(n, g string) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueBoolean, Required: true}
	}
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/service-deployment-artifact-source", phase5ID("artifactId", "ArtifactID"), text("repository", "Repository"), phase5Digest("digest", "Digest"), text("manifestPath", "ManifestPath"), text("bundlePath", "BundlePath"), text("policyPath", "PolicyPath")),
		phase5Schema("vegastack-labs.dev/service-deployment-provider-binding", ref("binding", "Binding", "vegastack-labs.dev/service-deployment-binding"), phase5ID("serviceBindingId", "ServiceBindingID"), text("destinationUuid", "DestinationUUID"), text("serverUuid", "ServerUUID"), phase5Positive("serverId", "ServerID"), phase5ID("mutationReferenceId", "MutationReferenceID"), phase5ID("runtimeReferenceId", "RuntimeReferenceID"), boolean("exclusiveOwnership", "ExclusiveOwnership"), FieldDefinition{JSONName: "artifacts", GoName: "Artifacts", Kind: ValueArray, Required: true, ItemRef: "vegastack-labs.dev/service-deployment-artifact-source", MinItems: intPointer(1), MaxItems: intPointer(128)}),
		phase5Schema("vegastack-labs.dev/service-deployment-draft-request", phase5ID("serviceId", "ServiceID"), phase5ID("artifactId", "ArtifactID"), phase5Enum("action", "Action", "deploy", "rollback"), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey"), phase5Digest("reasonDigest", "ReasonDigest")),
		phase5Schema("vegastack-labs.dev/service-deployment-binding", phase5Digest("configurationDigest", "ConfigurationDigest"), phase5ID("serviceId", "ServiceID"), phase5ID("bindingId", "BindingID"), phase5Enum("dataPolicy", "DataPolicy", "stateless", "compatible", "unknown", "irreversible")),
		phase5Schema("vegastack-labs.dev/service-deployment-artifact", phase5ID("artifactId", "ArtifactID"), text("repository", "Repository"), phase5Digest("digest", "Digest"), phase5Digest("manifestSha", "ManifestSHA"), phase5Digest("bundleSha", "BundleSHA"), phase5Digest("policySha", "PolicySHA")),
		phase5Schema(serviceDeploymentRequestID, ref("definition", "Definition", serviceDefinitionID), ref("binding", "Binding", "vegastack-labs.dev/service-deployment-binding"), ref("artifact", "Artifact", "vegastack-labs.dev/service-deployment-artifact"), phase5Digest("artifactProofDigest", "ArtifactProofDigest"), phase5Enum("action", "Action", "deploy", "rollback"), phase5Nonnegative("expectedDeploymentRevision", "ExpectedDeploymentRevision"), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey"), phase5Digest("reasonDigest", "ReasonDigest")),
		phase5Schema("vegastack-labs.dev/service-deployment-record", FieldDefinition{JSONName: "providerReceiptId", GoName: "ProviderReceiptID", Kind: ValueString, OmitEmpty: true, MaxLength: intPointer(128)}, phase5Enum("providerStage", "ProviderStage", "validated", "patch_attempted", "configured", "deploy_attempted", "queued", "unknown"), ref("request", "Request", serviceDeploymentRequestID), phase5Positive("revision", "Revision"), phase5Enum("status", "Status", "succeeded", "partial", "failed"), phase5Digest("receiptDigest", "ReceiptDigest"), phase5Digest("runtimeDigest", "RuntimeDigest"), text("runningDigest", "RunningDigest"), boolean("running", "Running"), boolean("healthy", "Healthy"), phase5ID("planId", "PlanID"), phase5ID("runId", "RunID"), phase5Timestamp("completedAt", "CompletedAt")),
	}
}
