package metadata

func maintenanceSchemas() []SchemaDefinition {
	state := func(j, g string) FieldDefinition { return phase5Enum(j, g, "healthy", "stale", "failed", "unknown") }
	prereq := func(j, g string) FieldDefinition {
		return phase5Enum(j, g, "passed", "failed", "partial", "unknown", "unsupported")
	}
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/maintenance-finding", phase5ID("controlId", "ControlID"), state("status", "Status"), phase5ID("reasonCode", "ReasonCode")),
		phase5Schema("vegastack-labs.dev/maintenance-diagnosis", phase5ID("hostId", "HostID"), state("status", "Status"), phase5Digest("bindingDigest", "BindingDigest"), phase5Digest("observationDigest", "ObservationDigest"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Timestamp("observedAt", "ObservedAt"), accessBool("newAdmissionBlocked", "NewAdmissionBlocked"), phase5Enum("existingWorkloads", "ExistingWorkloads", "unchanged"), accessList("findings", "Findings", "vegastack-labs.dev/maintenance-finding", 128)),
		phase5Schema("vegastack-labs.dev/maintenance-target", phase5ID("hostId", "HostID"), phase5Digest("bindingDigest", "BindingDigest"), phase5Digest("observationDigest", "ObservationDigest"), state("diagnosis", "Diagnosis"), prereq("canary", "Canary"), prereq("drain", "Drain"), prereq("health", "Health"), prereq("recovery", "Recovery")),
		phase5Schema("vegastack-labs.dev/maintenance-incident", phase5Digest("responsibleHumanDigest", "ResponsibleHumanDigest"), phase5Digest("agentSessionDigest", "AgentSessionDigest"), phase5Digest("reasonDigest", "ReasonDigest"), phase5Timestamp("startedAt", "StartedAt"), phase5Timestamp("endedAt", "EndedAt"), accessStrings("evidenceDigests", "EvidenceDigests", 32)),
		phase5Schema("vegastack-labs.dev/maintenance-draft-request", phase5ID("declarationId", "DeclarationID"), phase5Positive("expectedRevision", "ExpectedRevision"), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Enum("action", "Action", "repair", "incident-reconciliation"), accessStrings("targetIds", "TargetIDs", 32), phase5ID("canaryHostId", "CanaryHostID"), nativeSetupOptionalText("canaryRunId", "CanaryRunID", 128), replacementOptionalRef("incident", "Incident", "vegastack-labs.dev/maintenance-incident"), phase5Digest("reasonDigest", "ReasonDigest")),
		phase5Schema("vegastack-labs.dev/maintenance-record", phase5Enum("action", "Action", "repair", "incident-reconciliation"), accessList("targets", "Targets", "vegastack-labs.dev/maintenance-target", 32), phase5ID("canaryHostId", "CanaryHostID"), nativeSetupOptionalText("canaryRunId", "CanaryRunID", 128), replacementOptionalRef("incident", "Incident", "vegastack-labs.dev/maintenance-incident"), phase5Digest("preparedByDigest", "PreparedByDigest"), phase5Digest("agentSessionDigest", "AgentSessionDigest"), phase5Timestamp("preparedAt", "PreparedAt"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Digest("reasonDigest", "ReasonDigest"), accessStrings("blockers", "Blockers", 64), accessBool("executionAvailable", "ExecutionAvailable")),
	}
}
func maintenanceEndpoints() []EndpointDefinition {
	out := []EndpointDefinition{phase5Endpoint("api.v1.maintenance.diagnose", "GET", "/api/v1/maintenance/hosts/{hostID}", "", "vegastack-labs.dev/maintenance-diagnosis", false), phase5Endpoint("api.v1.maintenance.drafts.create", "POST", "/api/v1/maintenance/drafts", "vegastack-labs.dev/maintenance-draft-request", declarationRevisionSchemaID, false)}
	for i := range out {
		out[i].OwnerPhase = "10"
		out[i].Availability = AvailabilityAvailable
	}
	return out
}
func maintenanceCommands() []CommandDefinition {
	flags := []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected operator profile."}}
	diagnose := phase4OperatorCommand([]string{"maintenance", "diagnose"}, "Diagnose recorded host baseline drift without contacting a host.", "", "vegastack-labs.dev/maintenance-diagnosis", RiskReadOnly, append(append([]FlagDefinition{}, flags...), FlagDefinition{Name: "--host-id", Kind: FlagValue, ValueName: "id", Required: true, Summary: "Select one exact host."}), []string{"maintenance", "diagnose", "--config", "fixture/client.json", "--host-id", "host-a", "--output", "json"})
	draft := phase4OperatorCommand([]string{"maintenance", "draft"}, "Record an inert exact repair or incident reconciliation draft; execution remains unsupported.", "vegastack-labs.dev/maintenance-draft-request", declarationRevisionSchemaID, RiskMutation, append(append([]FlagDefinition{}, flags...), FlagDefinition{Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one bounded inert maintenance request."}), []string{"maintenance", "draft", "--config", "fixture/client.json", "--file", "fixture/maintenance.json", "--output", "json"})
	repairFlags := append(append([]FlagDefinition{}, flags...), FlagDefinition{Name: "--host-id", Kind: FlagValue, ValueName: "id", Required: true, Summary: "Select the exact diagnosed repair host."}, FlagDefinition{Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read the existing complete bounded baseline host-action request."})
	repair := phase4OperatorCommand([]string{"maintenance", "repair"}, "Prepare one diagnosed host's existing baseline action; plan, acknowledgement and apply remain separate.", hostActionRequestID, "vegastack-labs.dev/host-action-submission", RiskMutation, repairFlags, []string{"maintenance", "repair", "--config", "fixture/client.json", "--host-id", "host-a", "--file", "fixture/host-action.json", "--output", "json"})
	repair.OwnerPhase = "10"
	diagnose.OwnerPhase = "10"
	draft.OwnerPhase = "10"
	return []CommandDefinition{diagnose, draft, repair}
}
