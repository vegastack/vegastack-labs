package metadata

const localSetupRequestID = "vegastack-labs.dev/local-setup-request"

func localSetupSchemas() []SchemaDefinition {
	readID := "vegastack-labs.dev/local-setup-read-grant"
	grantID := "vegastack-labs.dev/local-setup-effective-grant"
	grants := func(name, goName, ref string) FieldDefinition {
		return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueArray, Required: true, ItemRef: ref, MinItems: intPointer(1), MaxItems: intPointer(32)}
	}
	schemas := []SchemaDefinition{
		phase5Schema(readID, phase5ID("capability", "Capability"), phase5ID("resourceKind", "ResourceKind"), phase5ID("resourceId", "ResourceID")),
		phase5Schema(grantID, phase5ID("grantId", "GrantID"), phase5Enum("roleId", "RoleID", "reader", "author", "maintainer", "infrastructure-admin", "control-plane-admin"), phase5Enum("action", "Action", "read", "author", "acknowledge", "execute"), phase5ID("capability", "Capability"), phase5ID("resourceKind", "ResourceKind"), phase5ID("resourceId", "ResourceID"), phase5Enum("branch", "Branch", "none", "human")),
		phase5Schema(localSetupRequestID,
			phase5ID("setupId", "SetupID"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), phase5ID("initialHumanId", "InitialHumanID"),
			phase5Positive("serviceUid", "ServiceUID"), phase5Positive("initialAdministratorUid", "InitialAdministratorUID"),
			phase5Digest("profileSha256", "ProfileSHA256"), discoveryText("databasePath", "DatabasePath", 4096),
			discoveryText("releaseManifestPath", "ReleaseManifestPath", 4096), phase5Digest("releaseManifestDigest", "ReleaseManifestDigest"),
			discoveryText("releasePolicyPath", "ReleasePolicyPath", 4096), phase5Digest("releasePolicyDigest", "ReleasePolicyDigest"),
			phase5ID("executableAssetId", "ExecutableAssetID"), phase5ID("releaseBuildId", "ReleaseBuildID"), phase5Timestamp("expiresAt", "ExpiresAt"),
			discoveryText("requestNonce", "RequestNonce", 128), grants("initialReadGrants", "InitialReadGrants", readID), grants("initialEffectiveGrants", "InitialEffectiveGrants", grantID)),
	}
	review := schemas[len(schemas)-1]
	review.ID = "vegastack-labs.dev/local-setup-review-request"
	review.ArtifactPath = "schemas/v1/local-setup-review-request.schema.json"
	review.Fields = append([]FieldDefinition(nil), review.Fields...)
	for i := range review.Fields {
		if review.Fields[i].JSONName == "schema" {
			review.Fields[i].Enum = []string{review.ID}
		}
		if review.Fields[i].JSONName == "requestNonce" {
			review.Fields[i] = phase5Digest("requestNonceDigest", "RequestNonceDigest")
		}
	}
	return append(schemas, review)
}
