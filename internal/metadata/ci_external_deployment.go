package metadata

func ciExternalDeploymentSchemas() []SchemaDefinition {
	return []SchemaDefinition{phase5Schema("vegastack-labs.dev/ci-external-deployment-binding",
		phase5ID("bindingId", "BindingID"), phase5ID("executionBindingId", "ExecutionBindingID"), phase5ID("serviceId", "ServiceID"), phase5ID("artifactId", "ArtifactID"), phase5ID("executorId", "ExecutorID"), phase5ID("materialVersion", "MaterialVersion"), phase5ID("resolverId", "ResolverID"))}
}
