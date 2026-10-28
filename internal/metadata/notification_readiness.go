package metadata

const notificationPolicyID = "vegastack-labs.dev/notification-readiness-policy"
const notificationRequestID = "vegastack-labs.dev/notification-readiness-request"

func notificationReadinessSchemas() []SchemaDefinition {
	return []SchemaDefinition{
		phase5Schema(notificationPolicyID, phase5ID("targetId", "TargetID"), phase5ID("primaryHumanId", "PrimaryHumanID"), phase5ID("secondaryHumanId", "SecondaryHumanID"), phase5ID("primaryCredentialOwnerId", "PrimaryCredentialOwnerID"), phase5ID("secondaryCredentialOwnerId", "SecondaryCredentialOwnerID"), phase5Enum("primaryCredentialClass", "PrimaryCredentialClass", "fine-grained-pat", "github-app-installation"), phase5ID("secondaryChannelId", "SecondaryChannelID"), phase5ID("primaryReferenceId", "PrimaryReferenceID"), phase5ID("primaryMaterialVersion", "PrimaryMaterialVersion"), phase5ID("secondaryReferenceId", "SecondaryReferenceID"), phase5ID("secondaryMaterialVersion", "SecondaryMaterialVersion")),
		phase5Schema(notificationRequestID, phase5Enum("action", "Action", "canary-draft", "evidence-draft"), phase5ID("requestId", "RequestID"), FieldDefinition{JSONName: "runId", GoName: "RunID", Kind: ValueString, OmitEmpty: true, MaxLength: intPointer(128)}, phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
	}
}
func notificationReadinessEndpoints() []EndpointDefinition {
	e := phase5Endpoint("api.v1.operations.notification-readiness", "POST", "/api/v1/operations/notification-readiness", notificationRequestID, "vegastack-labs.dev/declaration-revision", false)
	e.OwnerPhase = "10"
	e.Availability = AvailabilityAvailable
	return []EndpointDefinition{e}
}
func notificationReadinessCommands() []CommandDefinition {
	c := phase5GateCommand([]string{"operations", "notification-readiness"}, "Prepare a fixed acknowledged notification test or inert G-011 evidence; never send while preparing.", notificationRequestID, "vegastack-labs.dev/declaration-revision", RiskMutation, []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected operator profile."}, {Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read a bounded inert preparation request."}}, []string{"operations", "notification-readiness", "--config", "fixture/client.json", "--file", "fixture/request.json"})
	c.OwnerPhase = "10"
	return []CommandDefinition{c}
}
