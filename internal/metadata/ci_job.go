package metadata

const ciJobRequestID = "vegastack-labs.dev/ci-job-request"

func ciJobSchemas() []SchemaDefinition {
	text := func(n, g string, max int) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(max)}
	}
	base := []FieldDefinition{phase5ID("enrollmentId", "EnrollmentID"), phase5ID("executionBindingId", "ExecutionBindingID"), text("runId", "RunID", 20), phase5Positive("attempt", "Attempt"), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey"), phase5Digest("reasonDigest", "ReasonDigest")}
	req := []FieldDefinition{{JSONName: "deploymentDigest", GoName: "DeploymentDigest", Kind: ValueString, OmitEmpty: true, Pattern: `^sha256:[a-f0-9]{64}$`}, discoveryRef("definition", "Definition", "vegastack-labs.dev/ci-enrollment-definition"), phase5ID("executionBindingId", "ExecutionBindingID"), phase5Digest("executionBindingDigest", "ExecutionBindingDigest"), phase5ID("hostId", "HostID"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), phase5Digest("hostAdmissionDigest", "HostAdmissionDigest"), text("runId", "RunID", 20), phase5Positive("attempt", "Attempt"), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey"), phase5Digest("reasonDigest", "ReasonDigest")}
	binding := []FieldDefinition{phase5ID("bindingId", "BindingID"), phase5ID("hostId", "HostID"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), phase5Positive("targetRevision", "TargetRevision"), phase5Digest("targetDigest", "TargetDigest"), phase5ID("automationPrincipalId", "AutomationPrincipalID"), phase5Positive("callerUid", "CallerUID"), phase5ID("sshReferenceId", "SSHReferenceID"), phase5ID("sshMaterialVersion", "SSHMaterialVersion"), phase5ID("registrationReferenceId", "RegistrationReferenceID"), phase5ID("registrationMaterialVersion", "RegistrationMaterialVersion"), phase5ID("observerReferenceId", "ObserverReferenceID"), phase5ID("observerMaterialVersion", "ObserverMaterialVersion"), phase5ID("runtimeProfileId", "RuntimeProfileID"), phase5Digest("runtimeDigest", "RuntimeDigest"), text("runnerGroupName", "RunnerGroupName", 128), phase5Positive("maximumSeconds", "MaximumSeconds")}
	return []SchemaDefinition{phase5Schema("vegastack-labs.dev/ci-job-draft-request", base...), phase5Schema(ciJobRequestID, req...), phase5Schema("vegastack-labs.dev/ci-job-execution-binding", binding...)}
}
func ciJobEndpoints() []EndpointDefinition {
	e := phase5Endpoint("api.v1.ci.jobs.drafts.create", "POST", "/api/v1/ci/jobs/drafts", "vegastack-labs.dev/ci-job-draft-request", declarationRevisionSchemaID, false)
	e.OwnerPhase = "9"
	e.Availability = AvailabilityAvailable
	return []EndpointDefinition{e}
}
func ciJobCommands() []CommandDefinition {
	c := phase4OperatorCommand([]string{"ci", "job", "draft"}, "Draft one inert exact CI job for human plan acknowledgement.", "vegastack-labs.dev/ci-job-draft-request", declarationRevisionSchemaID, RiskMutation, []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected operator profile."}, {Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one exact CI job draft request."}}, []string{"ci", "job", "draft", "--config", "fixture/client.json", "--file", "fixture/ci-job.json", "--output", "json"})
	c.OwnerPhase = "9"
	return []CommandDefinition{c}
}
