package metadata

const serviceDefinitionID = "vegastack-labs.dev/service-definition"
const serviceImportRequestID = "vegastack-labs.dev/service-import-request"

func serviceCatalogSchemas() []SchemaDefinition {
	text := func(n, g string, max int) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(max)}
	}
	optionalText := func(n, g string, max int) FieldDefinition {
		f := text(n, g, max)
		f.Required = false
		f.OmitEmpty = true
		return f
	}
	ref := func(n, g, id string) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueObject, Required: true, Ref: id}
	}
	return []SchemaDefinition{
		phase5Schema(serviceDefinitionID, phase5ID("serviceId", "ServiceID"), phase5ID("environmentId", "EnvironmentID"), phase5ID("ownerId", "OwnerID"), phase5ID("hostId", "HostID"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), phase5ID("bindingId", "BindingID"), phase5Digest("bindingDigest", "BindingDigest")),
		phase5Schema("vegastack-labs.dev/service-import-draft-request", phase5ID("serviceId", "ServiceID"), phase5ID("bindingId", "BindingID"), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey"), phase5Digest("reasonDigest", "ReasonDigest")),
		phase5Schema(serviceImportRequestID, ref("definition", "Definition", serviceDefinitionID), phase5Digest("observationDigest", "ObservationDigest"), phase5Nonnegative("expectedServiceRevision", "ExpectedServiceRevision"), phase5Nonnegative("expectedDeclarationRevision", "ExpectedDeclarationRevision"), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey"), phase5Digest("reasonDigest", "ReasonDigest")),
		phase5Schema("vegastack-labs.dev/service-record", ref("definition", "Definition", serviceDefinitionID), phase5Positive("revision", "Revision"), phase5Enum("registrationStatus", "RegistrationStatus", "registered"), phase5Enum("hostAdmission", "HostAdmission", "not-verified"), phase5Timestamp("registeredAt", "RegisteredAt"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema("vegastack-labs.dev/service-list", FieldDefinition{JSONName: "services", GoName: "Services", Kind: ValueArray, Required: true, ItemRef: "vegastack-labs.dev/service-record", MaxItems: intPointer(100)}, optionalText("nextAfter", "NextAfter", 128), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		{ID: "vegastack-labs.dev/service-read-query", Version: "1.0.0", ArtifactPath: schemaPath("vegastack-labs.dev/service-read-query"), Fields: []FieldDefinition{optionalText("after", "After", 128), {JSONName: "limit", GoName: "Limit", Kind: ValueInteger, OmitEmpty: true, Minimum: int64Pointer(1), Maximum: int64Pointer(100)}}},
		phase5Schema("vegastack-labs.dev/service-observation", phase5ID("serviceId", "ServiceID"), phase5Digest("bindingDigest", "BindingDigest"), phase5Timestamp("observedAt", "ObservedAt"), phase5Enum("hostingState", "HostingState", "observed", "unavailable", "unknown", "not-configured"), phase5Enum("hostingReason", "HostingReason", "observed", "not-configured", "credential-unavailable", "provider-unavailable"), text("providerStatus", "ProviderStatus", 128), optionalText("configuredImage", "ConfiguredImage", 1024), phase5Enum("artifactState", "ArtifactState", "observed", "unavailable", "unknown", "not-configured"), phase5Enum("artifactReason", "ArtifactReason", "observed", "not-configured", "credential-unavailable", "provider-unavailable"), optionalText("artifactDigest", "ArtifactDigest", 256), phase5Enum("artifactKind", "ArtifactKind", "image", "index", "unknown"), phase5Enum("scanState", "ScanState", "not-scanned", "pending", "running", "error", "unavailable", "passed", "findings", "unknown"), phase5Enum("signatureState", "SignatureState", "unverified"), phase5Enum("provenanceState", "ProvenanceState", "unverified"), phase5Enum("runningDigestState", "RunningDigestState", "unknown"), phase5Enum("healthState", "HealthState", "unknown"), phase5Enum("hostAdmission", "HostAdmission", "not-verified"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema("vegastack-labs.dev/coolify-service-binding", text("origin", "Origin", 2048), phase5Positive("teamId", "TeamID"), phase5Positive("projectId", "ProjectID"), phase5Positive("environmentId", "EnvironmentID"), phase5Positive("destinationId", "DestinationID"), text("projectUuid", "ProjectUUID", 128), text("environment", "Environment", 128), text("applicationUuid", "ApplicationUUID", 128), text("destinationType", "DestinationType", 128), phase5ID("observationReferenceId", "ObservationReferenceID")),
		phase5Schema("vegastack-labs.dev/harbor-service-binding", text("origin", "Origin", 2048), text("project", "Project", 256), text("repository", "Repository", 512), text("artifactDigest", "ArtifactDigest", 256), text("robotUsername", "RobotUsername", 256), phase5ID("observationReferenceId", "ObservationReferenceID")),
		phase5Schema("vegastack-labs.dev/service-provider-binding", phase5ID("bindingId", "BindingID"), phase5ID("serviceId", "ServiceID"), phase5ID("environmentId", "EnvironmentID"), phase5ID("ownerId", "OwnerID"), phase5ID("hostId", "HostID"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), FieldDefinition{JSONName: "coolify", GoName: "Coolify", Kind: ValueObject, Required: true, Nullable: true, Ref: "vegastack-labs.dev/coolify-service-binding"}, replacementOptionalRef("harbor", "Harbor", "vegastack-labs.dev/harbor-service-binding")),
	}
}
