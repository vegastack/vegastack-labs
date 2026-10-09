package metadata

const hostReplacementRequestID = "vegastack-labs.dev/host-replacement-request"
const hostAliasClaimRequestID = "vegastack-labs.dev/host-alias-claim-request"
const hostReplacementContinuityReferenceID = "vegastack-labs.dev/host-replacement-continuity-reference"

func replacementOptionalRef(name, goName, ref string) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueObject, Nullable: true, OmitEmpty: true, Ref: ref}
}
func replacementIDs(name, goName string, min, max int) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueArray, Required: true, ItemKind: ValueString, MinItems: intPointer(min), MaxItems: intPointer(max), UniqueItems: true}
}
func hostReplacementSchemas() []SchemaDefinition {
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/host-replacement-request",
			phase5ID("replacementId", "ReplacementID"),
			phase5ID("oldHostId", "OldHostID"),
			phase5ID("newHostId", "NewHostID"),
			phase5ID("profileId", "ProfileID"),
			phase5ID("roleDeclarationId", "RoleDeclarationID"),
			phase5ID("proposedRoleDeclarationId", "ProposedRoleDeclarationID"),
			phase5ID("idempotencyKey", "IdempotencyKey"),
			phase5Digest("oldIdentityDigest", "OldIdentityDigest"),
			phase5Digest("newIdentityDigest", "NewIdentityDigest"),
			phase5Digest("oldTargetDigest", "OldTargetDigest"),
			phase5Digest("newTargetDigest", "NewTargetDigest"),
			phase5Digest("oldSshHostKeyDigest", "OldSSHHostKeyDigest"),
			phase5Digest("newSshHostKeyDigest", "NewSSHHostKeyDigest"),
			phase5Digest("profileLockDigest", "ProfileLockDigest"),
			phase5Digest("oldRoleBindingDigest", "OldRoleBindingDigest"),
			phase5Digest("proposedRoleBindingDigest", "ProposedRoleBindingDigest"),
			phase5Digest("preservedPreimageDigest", "PreservedPreimageDigest"),
			phase5Positive("oldTargetRevision", "OldTargetRevision"),
			phase5Positive("newTargetRevision", "NewTargetRevision"),
			phase5Positive("roleDeclarationRevision", "RoleDeclarationRevision"),
			phase5Positive("proposedRoleDeclarationRevision", "ProposedRoleDeclarationRevision"),
			phase5Nonnegative("expectedDeclarationRevision", "ExpectedDeclarationRevision"),
			phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5Enum("operation", "Operation", "freeze", "commit"),
			phase5Enum("restorationClass", "RestorationClass", "control-database", "stateless-role"),
			FieldDefinition{JSONName: "aliasBindings", GoName: "AliasBindings", Kind: ValueArray, Required: true, ItemRef: "vegastack-labs.dev/host-replacement-alias-binding", MinItems: intPointer(1), MaxItems: intPointer(32)},
			replacementIDs("payloadIds", "PayloadIDs", 0, 32),
			replacementIDs("volumeIds", "VolumeIDs", 0, 16),
			replacementIDs("resourceIds", "ResourceIDs", 0, 32),
			replacementOptionalRef("source", "Source", "vegastack-labs.dev/host-replacement-source-reference"),
			discoveryRef("osPreparation", "OSPreparation", "vegastack-labs.dev/host-replacement-os-preparation")),
		phase5Schema("vegastack-labs.dev/host-replacement-alias-binding",
			phase5ID("aliasId", "AliasID"),
			phase5ID("ownerHostId", "OwnerHostID"),
			phase5Digest("ownerIdentityDigest", "OwnerIdentityDigest"),
			phase5Positive("ownerRevision", "OwnerRevision"),
			phase5Positive("ownershipGeneration", "OwnershipGeneration")),
		phase5Schema("vegastack-labs.dev/host-replacement-source-reference",
			phase5ID("pointId", "PointID"),
			phase5ID("custodyReferenceId", "CustodyReferenceID"),
			phase5Digest("manifestDigest", "ManifestDigest"),
			phase5Digest("sourceBindingDigest", "SourceBindingDigest"),
			phase5Digest("custodyBindingDigest", "CustodyBindingDigest")),
		phase5Schema("vegastack-labs.dev/host-replacement-os-preparation",
			phase5Enum("method", "Method", "administrator-prepared"),
			phase5ID("observationId", "ObservationID"),
			phase5Digest("observationDigest", "ObservationDigest"),
			phase5Digest("hostIdentityDigest", "HostIdentityDigest"),
			phase5Timestamp("confirmedAt", "ConfirmedAt")),
		phase5Schema("vegastack-labs.dev/host-replacement-submission",
			phase5ID("replacementId", "ReplacementID"),
			phase5ID("draftId", "DraftID"),
			phase5ID("declarationId", "DeclarationID"),
			phase5Digest("contentDigest", "ContentDigest"),
			phase5Nonnegative("stateRevision", "StateRevision"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema("vegastack-labs.dev/host-replacement-state",
			phase5ID("replacementId", "ReplacementID"),
			phase5ID("declarationId", "DeclarationID"),
			phase5ID("oldHostId", "OldHostID"),
			phase5ID("newHostId", "NewHostID"),
			phase5Digest("bindingDigest", "BindingDigest"),
			phase5Digest("oldIdentityDigest", "OldIdentityDigest"),
			phase5Digest("newIdentityDigest", "NewIdentityDigest"),
			phase5Digest("roleBindingDigest", "RoleBindingDigest"),
			phase5Positive("declarationRevision", "DeclarationRevision"),
			phase5Positive("priorOwnershipGeneration", "PriorOwnershipGeneration"),
			phase5Positive("proposedOwnershipGeneration", "ProposedOwnershipGeneration"),
			phase5Nonnegative("roleIntentRevision", "RoleIntentRevision"),
			phase5Nonnegative("stateRevision", "StateRevision"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5Enum("status", "Status", "staged", "frozen", "restore-pending", "verification-required", "qualification-required", "committed"),
			phase5Enum("restorationClass", "RestorationClass", "control-database", "stateless-role"),
			FieldDefinition{JSONName: "aliasBindings", GoName: "AliasBindings", Kind: ValueArray, Required: true, ItemRef: "vegastack-labs.dev/host-replacement-alias-binding", MinItems: intPointer(1), MaxItems: intPointer(32)},
			phase5Enum("nextAction", "NextAction", "approve-freeze", "resolve-fences", "stage-restore", "restart-candidate", "verify-restore", "qualify-replacement", "prepare-commit", "none"),
			accessStrings("blockers", "Blockers", 32),
			phase5NullableID("planId", "PlanID"),
			phase5NullableID("runId", "RunID"),
			phase5NullableID("restorePlanId", "RestorePlanID"),
			baselineOptionalDigest("freezeEventDigest", "FreezeEventDigest"),
			baselineOptionalDigest("restorationReceiptDigest", "RestorationReceiptDigest"),
			baselineOptionalDigest("admissionSnapshotDigest", "AdmissionSnapshotDigest"),
			baselineOptionalDigest("continuityDigest", "ContinuityDigest")),
		phase5Schema("vegastack-labs.dev/host-alias-claim-request",
			phase5ID("hostId", "HostID"),
			phase5ID("idempotencyKey", "IdempotencyKey"),
			phase5Digest("hostIdentityDigest", "HostIdentityDigest"),
			replacementIDs("aliasIds", "AliasIDs", 1, 32),
			phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema("vegastack-labs.dev/host-replacement-continuity-reference",
			phase5ID("replacementId", "ReplacementID"),
			phase5ID("sourcePointId", "SourcePointID"),
			phase5Digest("digest", "Digest"),
			phase5Digest("sourceBindingDigest", "SourceBindingDigest"),
			phase5Nonnegative("sourceAliasHighWatermark", "SourceAliasHighWatermark"),
			phase5Nonnegative("currentAliasHighWatermark", "CurrentAliasHighWatermark")),
	}
}
func hostReplacementEndpoints() []EndpointDefinition {
	result := []EndpointDefinition{
		phase5Endpoint("api.v1.host-replacements.create", "POST", "/api/v1/host-replacements", hostReplacementRequestID, "vegastack-labs.dev/host-replacement-submission", false),
		phase5Endpoint("api.v1.host-replacements.get", "GET", "/api/v1/host-replacements/{replacementId}", "", "vegastack-labs.dev/host-replacement-state", false),
	}
	for i := range result {
		result[i].OwnerPhase = "6"
		result[i].Availability = AvailabilityAvailable
	}
	return result
}
