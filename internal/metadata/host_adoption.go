package metadata

const (
	identityConfirmationID = "vegastack-labs.dev/host-identity-confirmation"
	adoptionRequestID      = "vegastack-labs.dev/host-adoption-request"
	adoptionSubmissionID   = "vegastack-labs.dev/host-adoption-submission"
	managedHostID          = "vegastack-labs.dev/managed-host"
)

func hostAdoptionSchemas() []SchemaDefinition {
	return []SchemaDefinition{
		phase5Schema(identityConfirmationID, phase5Digest("targetDigest", "TargetDigest"), phase5Positive("targetRevision", "TargetRevision"), phase5Digest("identityDigest", "IdentityDigest"), phase5Enum("identityClass", "IdentityClass", "physical", "qualified-virtual"), phase5Enum("identityKind", "IdentityKind", "product-serial", "product-uuid"), phase5Timestamp("confirmedAt", "ConfirmedAt")),
		phase5Schema(adoptionRequestID, phase5ID("hostId", "HostID"), phase5ID("observationId", "ObservationID"), phase5Digest("observationDigest", "ObservationDigest"), phase5ID("idempotencyKey", "IdempotencyKey"), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), discoveryRef("confirmation", "Confirmation", identityConfirmationID)),
		phase5Schema(adoptionSubmissionID, phase5ID("draftId", "DraftID"), phase5ID("declarationId", "DeclarationID"), phase5Digest("contentDigest", "ContentDigest"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema(managedHostID, FieldDefinition{JSONName: "roleFoundation", GoName: "RoleFoundation", Kind: ValueObject, Nullable: true, OmitEmpty: true, Ref: "vegastack-labs.dev/host-role-foundation"}, phase5ID("hostId", "HostID"), phase5ID("targetId", "TargetID"), phase5ID("observationId", "ObservationID"), phase5ID("profileId", "ProfileID"), phase5Enum("identityClass", "IdentityClass", "physical", "qualified-virtual"), phase5Enum("status", "Status", "adopted-unadmitted"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
	}
}
func hostAdoptionEndpoints() []EndpointDefinition {
	result := []EndpointDefinition{
		phase5Endpoint("api.v1.host-adoptions.draft", "POST", "/api/v1/host-adoptions/draft", adoptionRequestID, adoptionSubmissionID, false),
		phase5Endpoint("api.v1.hosts.get", "GET", "/api/v1/hosts/{hostID}", "", managedHostID, false),
	}
	for i := range result {
		result[i].OwnerPhase = "6"
		result[i].Availability = AvailabilityAvailable
	}
	return result
}
