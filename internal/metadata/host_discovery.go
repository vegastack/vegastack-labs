package metadata

const (
	discoveryConsoleID         = "vegastack-labs.dev/host-discovery-console-confirmation"
	discoveryTargetID          = "vegastack-labs.dev/host-discovery-target"
	discoveryDraftID           = "vegastack-labs.dev/host-discovery-target-draft-request"
	discoveryRequestID         = "vegastack-labs.dev/host-discovery-request"
	discoveryFactID            = "vegastack-labs.dev/host-discovery-fact"
	discoveryObservationID     = "vegastack-labs.dev/host-observation"
	discoverySubmissionID      = "vegastack-labs.dev/host-discovery-submission"
	discoveryDraftSubmissionID = "vegastack-labs.dev/host-discovery-target-draft-submission"
)

func discoveryText(name, goName string, max int) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(max)}
}
func discoveryArray(name, goName, ref string, max int) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueArray, Required: true, ItemRef: ref, MaxItems: intPointer(max)}
}
func discoveryRef(name, goName, ref string) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueObject, Required: true, Ref: ref}
}
func hostDiscoverySchemas() []SchemaDefinition {
	return []SchemaDefinition{
		phase5Schema(discoveryConsoleID, phase5Digest("targetDigest", "TargetDigest"), phase5Enum("method", "Method", "administrator-verified-console")),
		phase5Schema(discoveryTargetID,
			phase5ID("targetId", "TargetID"), phase5Positive("revision", "Revision"),
			discoveryText("address", "Address", 45), phase5Positive("port", "Port"),
			discoveryText("user", "User", 32), discoveryText("hostKey", "HostKey", 2048),
			phase5ID("profileId", "ProfileID"), phase5ID("credentialReferenceId", "CredentialReferenceID"), phase5ID("materialVersion", "MaterialVersion"),
			discoveryText("expectedOs", "ExpectedOS", 32), discoveryText("expectedVersion", "ExpectedVersion", 32), discoveryText("expectedArchitecture", "ExpectedArchitecture", 32),
			phase5NullableID("inventoryDraftId", "InventoryDraftID"), phase5Nonnegative("inventoryDraftRevision", "InventoryDraftRevision"), phase5NullableID("assetId", "AssetID"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			FieldDefinition{JSONName: "credentialMode", GoName: "CredentialMode", Kind: ValueString, Nullable: true, OmitEmpty: true, Enum: []string{"preloaded-discovery"}},
			FieldDefinition{JSONName: "credentialPublicKeyDigest", GoName: "CredentialPublicKeyDigest", Kind: ValueString, Nullable: true, OmitEmpty: true, Pattern: "^sha256:[a-f0-9]{64}$"}),
		phase5Schema(discoveryDraftID,
			discoveryRef("target", "Target", discoveryTargetID), phase5Enum("action", "Action", "activate", "revoke"),
			phase5Nonnegative("expectedTargetRevision", "ExpectedTargetRevision"), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"),
			phase5ID("idempotencyKey", "IdempotencyKey"), FieldDefinition{JSONName: "consoleConfirmation", GoName: "ConsoleConfirmation", Kind: ValueObject, Nullable: true, OmitEmpty: true, Ref: discoveryConsoleID}),
		phase5Schema(discoveryDraftSubmissionID,
			phase5ID("draftId", "DraftID"), phase5ID("declarationId", "DeclarationID"), phase5Digest("contentDigest", "ContentDigest"),
			phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema(discoveryRequestID,
			phase5ID("targetId", "TargetID"), phase5Positive("targetRevision", "TargetRevision"), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey")),
		phase5Schema(discoveryFactID,
			phase5ID("name", "Name"), discoveryText("value", "Value", 256), phase5ID("operation", "Operation"), phase5Timestamp("capturedAt", "CapturedAt")),
		phase5Schema(discoveryObservationID,
			phase5ID("observationId", "ObservationID"), phase5ID("targetId", "TargetID"), phase5Positive("targetRevision", "TargetRevision"), phase5Digest("targetDigest", "TargetDigest"),
			phase5ID("collector", "Collector"), phase5Version("collectorVersion", "CollectorVersion"),
			phase5Timestamp("observedAt", "ObservedAt"), phase5Timestamp("expiresAt", "ExpiresAt"),
			phase5Enum("status", "Status", "untrusted", "incomplete"),
			discoveryArray("facts", "Facts", discoveryFactID, 768),
			FieldDefinition{JSONName: "blockers", GoName: "Blockers", Kind: ValueArray, Required: true, ItemKind: ValueString, MaxItems: intPointer(64)},
			phase5Digest("contentDigest", "ContentDigest"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema(discoverySubmissionID,
			discoveryRef("observation", "Observation", discoveryObservationID), phase5Bool("created", "Created")),
	}
}
func hostDiscoveryEndpoints() []EndpointDefinition {
	result := []EndpointDefinition{
		phase5Endpoint("api.v1.host-discovery-targets.draft", "POST", "/api/v1/host-discovery-targets/draft", discoveryDraftID, discoveryDraftSubmissionID, true),
		phase5Endpoint("api.v1.host-observations.create", "POST", "/api/v1/host-observations", discoveryRequestID, discoverySubmissionID, true),
		phase5Endpoint("api.v1.host-observations.get", "GET", "/api/v1/host-observations/{observationID}", "", discoveryObservationID, true),
	}
	for i := range result {
		result[i].OwnerPhase = "6"
		result[i].Availability = AvailabilityAvailable
	}
	return result
}
