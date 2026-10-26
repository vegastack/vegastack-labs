package metadata

func hostingLifecycleSchemas() []SchemaDefinition {
	text := func(n, g string) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(1024)}
	}
	ref := func(n, g, id string) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueObject, Required: true, Ref: id}
	}
	action := func() FieldDefinition {
		return phase5Enum("action", "Action", "resources.apply")
	}
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/hosting-owned-resource", phase5Enum("kind", "Kind", "coolify-project", "coolify-environment", "coolify-application", "coolify-service", "harbor-project", "harbor-retention", "harbor-robot"), text("externalId", "ExternalID"), text("parentId", "ParentID")),
		phase5Schema("vegastack-labs.dev/hosting-lifecycle-profile", phase5ID("bindingId", "BindingID"), phase5ID("targetId", "TargetID"), text("configurationPath", "ConfigurationPath"), phase5Digest("configurationDigest", "ConfigurationDigest"), phase5ID("mutationReferenceId", "MutationReferenceID"), phase5ID("platformReferenceId", "PlatformReferenceID")),
		phase5Schema("vegastack-labs.dev/hosting-lifecycle-draft-request", phase5ID("targetId", "TargetID"), action(), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey"), phase5Digest("reasonDigest", "ReasonDigest")),
		phase5Schema("vegastack-labs.dev/hosting-lifecycle-request", phase5ID("targetId", "TargetID"), phase5ID("bindingId", "BindingID"), phase5Digest("configurationDigest", "ConfigurationDigest"), phase5Digest("observedDigest", "ObservedDigest"), action(), phase5Nonnegative("expectedLifecycleRevision", "ExpectedLifecycleRevision"), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey"), phase5Digest("reasonDigest", "ReasonDigest")),
		phase5Schema("vegastack-labs.dev/hosting-lifecycle-record", ref("request", "Request", "vegastack-labs.dev/hosting-lifecycle-request"), FieldDefinition{JSONName: "ownedResources", GoName: "OwnedResources", Kind: ValueArray, Required: true, ItemRef: "vegastack-labs.dev/hosting-owned-resource", MinItems: intPointer(0), MaxItems: intPointer(512)}, phase5Positive("revision", "Revision"), phase5Enum("status", "Status", "succeeded", "partial", "failed"), phase5Digest("resultDigest", "ResultDigest"), phase5ID("planId", "PlanID"), phase5ID("runId", "RunID"), phase5Timestamp("completedAt", "CompletedAt")),
	}
}
func hostingLifecycleEndpoints() []EndpointDefinition {
	out := []EndpointDefinition{phase5Endpoint("api.v1.hosting.lifecycle-drafts.create", "POST", "/api/v1/hosting/lifecycle-drafts", "vegastack-labs.dev/hosting-lifecycle-draft-request", declarationRevisionSchemaID, false), phase5Endpoint("api.v1.hosting.lifecycle.get", "GET", "/api/v1/hosting/{targetID}/lifecycle", "", "vegastack-labs.dev/hosting-lifecycle-record", true)}
	for i := range out {
		out[i].OwnerPhase = "8"
		out[i].Availability = AvailabilityAvailable
	}
	return out
}
func hostingLifecycleCommands() []CommandDefinition {
	var out []CommandDefinition
	for _, a := range []string{"draft", "show"} {
		flags := []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected operator profile."}}
		args := []string{"hosting", "lifecycle", a, "--config", "fixture/client.json"}
		request, data, risk := "", "vegastack-labs.dev/hosting-lifecycle-record", RiskReadOnly
		if a == "draft" {
			flags = append(flags, FlagDefinition{Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one inert hosting lifecycle request."})
			args = append(args, "--file", "fixture/hosting.json")
			request = "vegastack-labs.dev/hosting-lifecycle-draft-request"
			data = declarationRevisionSchemaID
			risk = RiskMutation
		} else {
			flags = append(flags, FlagDefinition{Name: "--target-id", Kind: FlagValue, ValueName: "id", Required: true, Summary: "Select one exact hosting target."})
			args = append(args, "--target-id", "hosting-a")
		}
		c := phase4OperatorCommand([]string{"hosting", "lifecycle", a}, "Prepare or inspect one exact hosting lifecycle.", request, data, risk, flags, append(args, "--output", "json"))
		c.OwnerPhase = "8"
		out = append(out, c)
	}
	return out
}
