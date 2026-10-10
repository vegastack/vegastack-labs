package metadata

func nativeSlackFixtureSchemas() []SchemaDefinition {
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/native-slack-fixture-scope", nativeSetupOptionalBool(), nativeSetupOptionalUID("controlServiceUid", "ControlServiceUID"), nativeSetupOptionalUID("controlServiceGid", "ControlServiceGID"), phase5ID("guestInstanceId", "GuestInstanceID"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), phase5Digest("sshHostKeyDigest", "SSHHostKeyDigest"), phase5Digest("setupHostIdentityDigest", "SetupHostIdentityDigest"), FieldDefinition{JSONName: "sourceCommit", GoName: "SourceCommit", Kind: ValueString, Required: true, Pattern: "^[0-9a-f]{40}$"}, phase5Digest("executableDigest", "ExecutableDigest"), phase5Timestamp("issuedAt", "IssuedAt"), phase5Timestamp("expiresAt", "ExpiresAt"), nativeSlackID("workspaceId", "WorkspaceID"), nativeSlackID("userId", "UserID"), nativeSlackID("channelId", "ChannelID"), phase5ID("approveActionId", "ApproveActionID"), phase5ID("rejectActionId", "RejectActionID"), phase5ID("setupPlanId", "SetupPlanID"), phase5Digest("setupPlanDigest", "SetupPlanDigest"), phase5Digest("setupRequestDigest", "SetupRequestDigest"), phase5Digest("appTokenDigest", "AppTokenDigest"), phase5Digest("botTokenDigest", "BotTokenDigest"), phase5Digest("tlsCertificateDigest", "TLSCertificateDigest")),
		phase5Schema("vegastack-labs.dev/native-slack-fixture-approval", phase5ID("planId", "PlanID"), phase5Digest("planDigest", "PlanDigest"), phase5Digest("targetDigest", "TargetDigest"), phase5Digest("reasonDigest", "ReasonDigest"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Timestamp("expiresAt", "ExpiresAt"), phase5Enum("action", "Action", "approve", "reject")),
		phase5Schema("vegastack-labs.dev/native-slack-fixture-approval-list", accessList("approvals", "Approvals", "vegastack-labs.dev/native-slack-fixture-approval", 48)),
	}
}

func nativeSlackID(name, goName string) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueString, Required: true, Pattern: `^[A-Z][A-Z0-9]{1,63}$`}
}

func nativeSetupOptionalBool() FieldDefinition {
	f := accessBool("runControlSetup", "RunControlSetup")
	f.Required = false
	f.OmitEmpty = true
	return f
}
func nativeSetupOptionalUID(name, goName string) FieldDefinition {
	f := phase5Positive(name, goName)
	f.Required = false
	f.OmitEmpty = true
	return f
}
