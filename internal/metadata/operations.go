package metadata

const operationsStatusID = "vegastack-labs.dev/operations-status-data"
const operationsObserveID = "vegastack-labs.dev/operations-observe-request"
const operationsAlertID = "vegastack-labs.dev/operations-alert"

func operationsSchemas() []SchemaDefinition {
	a := phase5Schema(operationsAlertID, phase5Digest("key", "Key"), phase5Digest("targetDigest", "TargetDigest"), phase5Enum("class", "Class", "source-health"), phase5Enum("severity", "Severity", "critical", "warning"), phase5Enum("observationState", "ObservationState", "healthy", "failed", "stale", "unknown", "unavailable"), phase5Enum("status", "Status", "clear", "pending", "open", "closed"), discoveryText("observedAt", "ObservedAt", 40), phase5Nonnegative("occurrences", "Occurrences"), phase5Nonnegative("generation", "Generation"))
	for _, f := range []struct{ j, g string }{{"firstFailure", "FirstFailure"}, {"lastFailure", "LastFailure"}, {"lastGood", "LastGood"}} {
		a.Fields = append(a.Fields, FieldDefinition{JSONName: f.j, GoName: f.g, Kind: ValueString, OmitEmpty: true, MaxLength: intPointer(40)})
	}
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/operations-beszel-binding", discoveryText("endpoint", "Endpoint", 2048), phase5ID("recordId", "RecordID"), phase5ID("targetId", "TargetID"), phase5ID("referenceId", "ReferenceID"), phase5ID("materialVersion", "MaterialVersion"), phase5Nonnegative("staleAfterSeconds", "StaleAfterSeconds")),
		phase5Schema("vegastack-labs.dev/operations-github-destination", discoveryText("endpoint", "Endpoint", 2048), discoveryText("repository", "Repository", 201), phase5Nonnegative("repositoryId", "RepositoryID"), phase5ID("targetId", "TargetID"), phase5ID("referenceId", "ReferenceID"), phase5ID("materialVersion", "MaterialVersion")),
		phase5Schema(operationsObserveID), a, phase5Schema(operationsStatusID, discoveryArray("alerts", "Alerts", operationsAlertID, 200), discoveryArray("deliveries", "Deliveries", outboxRecordDataSchemaID, 200), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Enum("notifications", "Notifications", "disabled", "configured"))}
}
func operationsEndpoints() []EndpointDefinition {
	r := []EndpointDefinition{phase5Endpoint("api.v1.operations.status", "GET", "/api/v1/operations", "", operationsStatusID, true), phase5Endpoint("api.v1.operations.observe", "POST", "/api/v1/operations/observe", operationsObserveID, operationsStatusID, false)}
	for i := range r {
		r[i].OwnerPhase = "10"
		r[i].Availability = AvailabilityAvailable
	}
	return r
}
func operationsCommands() []CommandDefinition {
	var r []CommandDefinition
	for _, action := range []string{"status", "observe"} {
		c := phase5GateCommand([]string{"operations", action}, "Inspect local alerts or collect server-owned source observations; no infrastructure mutation.", "", operationsStatusID, RiskReadOnly, []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected operator profile."}}, []string{"operations", action, "--config", "fixture/client.json"})
		if action == "observe" {
			c.RequestSchema = operationsObserveID
		}
		c.OwnerPhase = "10"
		r = append(r, c)
	}
	return r
}
