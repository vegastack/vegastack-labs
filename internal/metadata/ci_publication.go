package metadata

func ciPublicationSchemas() []SchemaDefinition {
	text := func(n, g string) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(4096)}
	}
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/ci-publication-draft-request", phase5ID("bindingId", "BindingID"), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey"), phase5Digest("reasonDigest", "ReasonDigest")),
		phase5Schema("vegastack-labs.dev/ci-publication-binding", phase5ID("bindingId", "BindingID"), phase5ID("enrollmentId", "EnrollmentID"), phase5ID("sourceRunId", "SourceRunID"), phase5ID("sourceStepId", "SourceStepID"), text("registryOrigin", "RegistryOrigin"), text("repository", "Repository"), phase5ID("referenceId", "ReferenceID"), phase5ID("materialVersion", "MaterialVersion"), text("candidatePath", "CandidatePath"), phase5Digest("candidateDigest", "CandidateDigest")),
	}
}
func ciPublicationEndpoints() []EndpointDefinition {
	e := phase5Endpoint("api.v1.ci.publications.drafts.create", "POST", "/api/v1/ci/publications/drafts", "vegastack-labs.dev/ci-publication-draft-request", declarationRevisionSchemaID, false)
	e.OwnerPhase = "9"
	e.Availability = AvailabilityAvailable
	return []EndpointDefinition{e}
}
func ciPublicationCommands() []CommandDefinition {
	c := phase4OperatorCommand([]string{"ci", "publication", "draft"}, "Draft verified OCI publication for exact human acknowledgement.", "vegastack-labs.dev/ci-publication-draft-request", declarationRevisionSchemaID, RiskMutation, []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected operator profile."}, {Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one exact publication draft request."}}, []string{"ci", "publication", "draft", "--config", "fixture/client.json", "--file", "fixture/publication.json", "--output", "json"})
	c.OwnerPhase = "9"
	return []CommandDefinition{c}
}
