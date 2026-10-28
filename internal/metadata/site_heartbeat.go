package metadata

const operationsHeartbeatBindingID = "vegastack-labs.dev/operations-heartbeat-binding"

func siteHeartbeatSchemas() []SchemaDefinition {
	return []SchemaDefinition{phase5Schema(operationsHeartbeatBindingID,
		discoveryText("endpoint", "Endpoint", 2048), discoveryText("bucket", "Bucket", 63), phase5Enum("objectKey", "ObjectKey", "heartbeat.json"), phase5Digest("siteDigest", "SiteDigest"), phase5ID("targetId", "TargetID"), phase5ID("referenceId", "ReferenceID"), phase5ID("materialVersion", "MaterialVersion"), phase5ID("policyId", "PolicyID"), discoveryText("policyVersion", "PolicyVersion", 64))}
}
