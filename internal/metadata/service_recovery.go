package metadata

const serviceRecoveryRequestID = "vegastack-labs.dev/service-recovery-request"

func serviceRecoverySchemas() []SchemaDefinition {
	text := func(n, g string, max int) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueString, Required: true, MaxLength: intPointer(max)}
	}
	ref := func(n, g, id string) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueObject, Required: true, Ref: id}
	}
	list := func(n, g, id string, max int) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueArray, Required: true, ItemRef: id, MinItems: intPointer(0), MaxItems: intPointer(max)}
	}
	boolean := func(n, g string) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueBoolean, Required: true}
	}
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/service-recovery-binding", phase5ID("policyId", "PolicyID"), phase5ID("serviceId", "ServiceID"), phase5Digest("configurationDigest", "ConfigurationDigest"), phase5Enum("dataClass", "DataClass", "platform", "workload", "registry"), phase5ID("consistencyProcedureId", "ConsistencyProcedureID"), phase5ID("sourceHostId", "SourceHostID"), phase5ID("targetHostId", "TargetHostID")),
		phase5Schema("vegastack-labs.dev/service-recovery-mount", text("destination", "Destination", 1024), phase5Enum("type", "Type", "volume", "bind"), text("source", "Source", 1024), text("targetSource", "TargetSource", 1024)),
		phase5Schema("vegastack-labs.dev/service-recovery-component", text("sourceContainerId", "SourceContainerID", 64), text("targetContainerId", "TargetContainerID", 64), phase5Digest("imageDigest", "ImageDigest"), list("mounts", "Mounts", "vegastack-labs.dev/service-recovery-mount", 64)),
		phase5Schema("vegastack-labs.dev/service-recovery-profile", ref("binding", "Binding", "vegastack-labs.dev/service-recovery-binding"), text("sourceProject", "SourceProject", 128), text("targetProject", "TargetProject", 128), list("components", "Components", "vegastack-labs.dev/service-recovery-component", 32), phase5ID("targetServiceId", "TargetServiceID"), phase5ID("sourceReferenceId", "SourceReferenceID"), phase5ID("targetReferenceId", "TargetReferenceID"), phase5ID("repositoryKeyReferenceId", "RepositoryKeyReferenceID"), phase5ID("repositoryId", "RepositoryID"), text("repositoryUrl", "RepositoryURL", 2048), text("repositoryRoot", "RepositoryRoot", 1024), text("exchangeRoot", "ExchangeRoot", 1024), text("resticBinaryPath", "ResticBinaryPath", 1024), text("architecture", "Architecture", 32), phase5Positive("maximumBytes", "MaximumBytes"), phase5Positive("recoveryObjectiveSeconds", "RecoveryObjectiveSeconds"), text("harborOrigin", "HarborOrigin", 2048), text("harborProject", "HarborProject", 256), text("harborRepository", "HarborRepository", 512), text("harborArtifactDigest", "HarborArtifactDigest", 71), text("harborUsername", "HarborUsername", 256), text("harborReferenceId", "HarborReferenceID", 128), text("platformOwnerId", "PlatformOwnerID", 128), text("cutoverIngressId", "CutoverIngressID", 128), text("cutoverBindingDigest", "CutoverBindingDigest", 71), text("cutoverOriginServiceId", "CutoverOriginServiceID", 128)),
		phase5Schema("vegastack-labs.dev/service-recovery-draft-request", phase5ID("serviceId", "ServiceID"), phase5ID("policyId", "PolicyID"), phase5Enum("action", "Action", "backup", "migration-freeze", "isolated-restore", "migration-cutover", "rollback-before-writers", "recovery-after-writers"), text("backupPointId", "BackupPointID", 128), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey"), phase5Digest("reasonDigest", "ReasonDigest")),
		phase5Schema(serviceRecoveryRequestID, ref("definition", "Definition", serviceDefinitionID), ref("binding", "Binding", "vegastack-labs.dev/service-recovery-binding"), phase5Enum("action", "Action", "backup", "migration-freeze", "isolated-restore", "migration-cutover", "rollback-before-writers", "recovery-after-writers"), text("backupPointId", "BackupPointID", 128), phase5Nonnegative("expectedRecoveryRevision", "ExpectedRecoveryRevision"), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey"), phase5Digest("reasonDigest", "ReasonDigest")),
		phase5Schema("vegastack-labs.dev/service-recovery-record", ref("request", "Request", serviceRecoveryRequestID), phase5Positive("revision", "Revision"), FieldDefinition{JSONName: "sourceImageDigests", GoName: "SourceImageDigests", Kind: ValueArray, Required: true, ItemKind: ValueString, MaxItems: intPointer(32)}, phase5Nonnegative("elapsedSeconds", "ElapsedSeconds"), phase5Enum("status", "Status", "succeeded", "partial", "failed", "blocked"), text("backupPointId", "BackupPointID", 128), text("snapshotId", "SnapshotID", 128), phase5Digest("manifestDigest", "ManifestDigest"), phase5Digest("contentDigest", "ContentDigest"), phase5Digest("runtimeDigest", "RuntimeDigest"), boolean("sourceResumed", "SourceResumed"), boolean("sourceFenced", "SourceFenced"), boolean("isolatedRestoreVerified", "IsolatedRestoreVerified"), boolean("targetWritersEnabled", "TargetWritersEnabled"), phase5Enum("nextAction", "NextAction", "none", "retry-with-new-plan", "recovery-required", "roll-forward-required", "route-proof-required"), phase5ID("planId", "PlanID"), phase5ID("runId", "RunID"), phase5Timestamp("completedAt", "CompletedAt")),
	}
}

func serviceRecoveryEndpoints() []EndpointDefinition {
	out := []EndpointDefinition{phase5Endpoint("api.v1.services.recovery-drafts.create", "POST", "/api/v1/services/recovery-drafts", "vegastack-labs.dev/service-recovery-draft-request", declarationRevisionSchemaID, false), phase5Endpoint("api.v1.services.recovery.get", "GET", "/api/v1/services/{serviceID}/recovery", "", "vegastack-labs.dev/service-recovery-record", true)}
	for i := range out {
		out[i].OwnerPhase = "8"
		out[i].Availability = AvailabilityAvailable
	}
	return out
}
func serviceRecoveryCommands() []CommandDefinition {
	var out []CommandDefinition
	for _, action := range []string{"draft", "show"} {
		flags := []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected operator profile."}}
		args := []string{"service", "recovery", action, "--config", "fixture/client.json"}
		request, data, risk := "", "vegastack-labs.dev/service-recovery-record", RiskReadOnly
		if action == "draft" {
			flags = append(flags, FlagDefinition{Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one inert workload recovery request."})
			args = append(args, "--file", "fixture/service-recovery.json")
			request = "vegastack-labs.dev/service-recovery-draft-request"
			data = declarationRevisionSchemaID
			risk = RiskMutation
		} else {
			flags = append(flags, FlagDefinition{Name: "--service-id", Kind: FlagValue, ValueName: "id", Required: true, Summary: "Select one exact service."})
			args = append(args, "--service-id", "service-a")
		}
		c := phase4OperatorCommand([]string{"service", "recovery", action}, "Prepare or inspect consistent workload recovery.", request, data, risk, flags, append(args, "--output", "json"))
		c.OwnerPhase = "8"
		out = append(out, c)
	}
	return out
}
