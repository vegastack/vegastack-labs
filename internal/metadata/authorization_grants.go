package metadata

const authorizationGrantBatchRequestID = "vegastack-labs.dev/authorization-grant-batch-request"

func authorizationGrantSchemas() []SchemaDefinition {
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/authorization-grant-change",
			phase5ID("grantId", "GrantID"), phase5Enum("change", "Change", "add", "revoke"),
			phase5Enum("roleId", "RoleID", "reader", "author", "maintainer", "infrastructure-admin", "control-plane-admin"),
			phase5Enum("action", "Action", "read", "author", "acknowledge", "execute"),
			phase5ID("capability", "Capability"), phase5ID("resourceKind", "ResourceKind"), phase5ID("resourceId", "ResourceID"),
			phase5Enum("branch", "Branch", "", "human")),
		phase5Schema(authorizationGrantBatchRequestID,
			phase5ID("principalId", "PrincipalID"), phase5Positive("expectedGrantRevision", "ExpectedGrantRevision"),
			phase5Nonnegative("expectedDeclarationRevision", "ExpectedDeclarationRevision"),
			phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5ID("idempotencyKey", "IdempotencyKey"), phase5Digest("reasonDigest", "ReasonDigest"),
			FieldDefinition{JSONName: "changes", GoName: "Changes", Kind: ValueArray, Required: true, ItemRef: "vegastack-labs.dev/authorization-grant-change", MinItems: intPointer(1), MaxItems: intPointer(32)}),
	}
}

func authorizationGrantCommand() CommandDefinition {
	c := phase5GateCommand([]string{"authorization", "grants", "draft"}, "Prepare exact grant additions or revocations; approval and apply remain separate.", "vegastack-labs.dev/authorization-grant-batch-request", "vegastack-labs.dev/declaration-revision", RiskMutation, []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected server profile."}, {Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one grant batch JSON file (32 KiB max)."}}, []string{"authorization", "grants", "draft", "--config", "fixture/server-profile.json", "--file", "fixture/grants.json", "--output", "json"})
	c.OwnerPhase = "6"
	return c
}
func authorizationGrantEndpoint() EndpointDefinition {
	e := phase5Endpoint("api.v1.authorization.grant-batches.create", "POST", "/api/v1/authorization/grant-batches", "vegastack-labs.dev/authorization-grant-batch-request", "vegastack-labs.dev/declaration-revision", false)
	e.Availability = AvailabilityAvailable
	e.OwnerPhase = "6"
	return e
}
