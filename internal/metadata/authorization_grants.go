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
			phase5ID("principalId", "PrincipalID"), FieldDefinition{JSONName: "lifecycleAction", GoName: "LifecycleAction", Kind: ValueString, OmitEmpty: true, Enum: []string{"onboard", "suspend", "resume", "offboard"}}, phase5Nonnegative("expectedGrantRevision", "ExpectedGrantRevision"),
			phase5Nonnegative("expectedDeclarationRevision", "ExpectedDeclarationRevision"),
			phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5ID("idempotencyKey", "IdempotencyKey"), phase5Digest("reasonDigest", "ReasonDigest"),
			FieldDefinition{JSONName: "changes", GoName: "Changes", Kind: ValueArray, Required: true, ItemRef: "vegastack-labs.dev/authorization-grant-change", MinItems: intPointer(0), MaxItems: intPointer(32)}),
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

func userLifecycleCommands() []CommandDefinition {
	var commands []CommandDefinition
	for _, action := range []string{"onboard", "suspend", "resume", "offboard"} {
		c := authorizationGrantCommand()
		c.Path = []string{"user", action}
		c.OwnerPhase = "7"
		c.Examples = []ExampleDefinition{{Summary: "Draft one exact user lifecycle change.", Arguments: []string{"user", action, "--config", "fixture/server-profile.json", "--file", "fixture/user.json", "--output", "json"}}}
		c.Summary = "Prepare one local user lifecycle declaration; acknowledgement and apply remain separate."
		commands = append(commands, c)
	}
	return commands
}
