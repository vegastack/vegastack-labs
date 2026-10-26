package metadata

func serviceConfigurationSchemas() []SchemaDefinition {
	optionalID := func(n, g string) FieldDefinition {
		f := phase5ID(n, g)
		f.Required = false
		f.OmitEmpty = true
		return f
	}
	text := func(n, g string, max int) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(max)}
	}
	bounded := func(n, g string, min, max int64) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueInteger, Required: true, Minimum: int64Pointer(min), Maximum: int64Pointer(max)}
	}
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/service-environment-secret", text("name", "Name", 128), phase5ID("referenceId", "ReferenceID"), phase5Digest("expectedFingerprint", "ExpectedFingerprint")),
		phase5Schema("vegastack-labs.dev/service-configuration", phase5Enum("environmentClass", "EnvironmentClass", "development", "production-like"), bounded("cpuQuotaPercent", "CPUQuotaPercent", 1, 100000), phase5Positive("memoryBytes", "MemoryBytes"), phase5Nonnegative("storageBytes", "StorageBytes"), bounded("port", "Port", 1, 65535), phase5Enum("exposure", "Exposure", "private", "public"), optionalID("exposurePolicyId", "ExposurePolicyID"), FieldDefinition{JSONName: "exposureHostname", GoName: "ExposureHostname", Kind: ValueString, OmitEmpty: true, MaxLength: intPointer(253)}, FieldDefinition{JSONName: "originPort", GoName: "OriginPort", Kind: ValueInteger, OmitEmpty: true, Minimum: int64Pointer(1), Maximum: int64Pointer(65535)}, FieldDefinition{JSONName: "originIdentityDigest", GoName: "OriginIdentityDigest", Kind: ValueString, OmitEmpty: true, Pattern: `^sha256:[a-f0-9]{64}$`}, text("healthPath", "HealthPath", 256), bounded("healthExpectedStatus", "HealthExpectedStatus", 100, 599), bounded("healthIntervalSeconds", "HealthIntervalSeconds", 1, 300), bounded("healthTimeoutSeconds", "HealthTimeoutSeconds", 1, 60), bounded("healthRetries", "HealthRetries", 1, 20), phase5Enum("dataClass", "DataClass", "stateless", "stateful"), optionalID("backupPolicyId", "BackupPolicyID"), optionalID("consistencyProcedureId", "ConsistencyProcedureID"), optionalID("recoveryRecordId", "RecoveryRecordID"), phase5Nonnegative("recoveryObjectiveSeconds", "RecoveryObjectiveSeconds"), phase5Enum("migration", "Migration", "none", "backward-compatible", "irreversible"), phase5Enum("rollback", "Rollback", "previous-artifact", "recovery-required"), FieldDefinition{JSONName: "secretReferenceIds", GoName: "SecretReferenceIDs", Kind: ValueArray, Required: true, ItemKind: ValueString, MaxItems: intPointer(32), UniqueItems: true}),
		phase5Schema("vegastack-labs.dev/service-capacity", phase5ID("hostId", "HostID"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), phase5Digest("targetDigest", "TargetDigest"), phase5Positive("cpuQuotaPercent", "CPUQuotaPercent"), phase5Positive("memoryBytes", "MemoryBytes"), phase5Nonnegative("storageBytes", "StorageBytes"), phase5Timestamp("observedAt", "ObservedAt"), phase5Timestamp("expiresAt", "ExpiresAt"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema("vegastack-labs.dev/service-configuration-status", phase5ID("serviceId", "ServiceID"), replacementOptionalRef("configuration", "Configuration", "vegastack-labs.dev/service-configuration"), FieldDefinition{JSONName: "configurationDigest", GoName: "ConfigurationDigest", Kind: ValueString, OmitEmpty: true, Pattern: `^sha256:[a-f0-9]{64}$`}, phase5Enum("placementState", "PlacementState", "eligible", "blocked", "unknown"), text("placementReason", "PlacementReason", 128), phase5Timestamp("observedAt", "ObservedAt"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
	}
}
