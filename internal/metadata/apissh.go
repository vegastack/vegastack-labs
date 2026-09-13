package metadata

const (
	apiSshRequestFrameHeaderSchemaID  = "vegastack-labs.dev/api-ssh-request-frame-header"
	apiSshResponseFrameHeaderSchemaID = "vegastack-labs.dev/api-ssh-response-frame-header"
)

func apiSshSchemas() []SchemaDefinition {
	protocol := FieldDefinition{JSONName: "protocol", GoName: "Protocol", Kind: ValueString, Required: true, Enum: []string{"vegastack-labs.api-ssh"}}
	version := FieldDefinition{JSONName: "version", GoName: "Version", Kind: ValueString, Required: true, Enum: []string{"1.0.0"}}
	requestID := FieldDefinition{JSONName: "requestId", GoName: "RequestID", Kind: ValueString, Required: true, Pattern: `^[a-z][a-z0-9._:-]{0,127}$`}
	length := func(name, goName string, maximum int64) FieldDefinition {
		return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueInteger, Required: true, Minimum: int64Pointer(0), Maximum: int64Pointer(maximum)}
	}
	return []SchemaDefinition{
		{
			ID:           apiSshRequestFrameHeaderSchemaID,
			Version:      "1.0.0",
			ArtifactPath: schemaPath(apiSshRequestFrameHeaderSchemaID),
			Fields: []FieldDefinition{
				protocol,
				version,
				requestID,
				{JSONName: "sshPrincipalId", GoName: "SSHPrincipalID", Kind: ValueString, Required: true, Pattern: `^[a-z][a-z0-9._:-]{0,127}$`},
				{JSONName: "deviceId", GoName: "DeviceID", Kind: ValueString, Required: true, Pattern: `^[a-z][a-z0-9._:-]{0,127}$`},
				{JSONName: "operation", GoName: "Operation", Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(512)},
				{JSONName: "arguments", GoName: "Arguments", Kind: ValueArray, Required: true, ItemKind: ValueString, MaxItems: intPointer(256)},
				{JSONName: "payloadDigest", GoName: "PayloadDigest", Kind: ValueString, Required: true, Pattern: `^sha256:[0-9a-f]{64}$`},
				length("declaredPayloadBytes", "DeclaredPayloadBytes", 8<<20),
				length("actualPayloadBytes", "ActualPayloadBytes", 8<<20),
				{JSONName: "recoveryEpoch", GoName: "RecoveryEpoch", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)},
			},
		},
		{
			ID:           apiSshResponseFrameHeaderSchemaID,
			Version:      "1.0.0",
			ArtifactPath: schemaPath(apiSshResponseFrameHeaderSchemaID),
			Fields: []FieldDefinition{
				protocol,
				version,
				requestID,
				length("declaredPayloadBytes", "DeclaredPayloadBytes", 24<<20),
				length("actualPayloadBytes", "ActualPayloadBytes", 24<<20),
			},
		},
	}
}
