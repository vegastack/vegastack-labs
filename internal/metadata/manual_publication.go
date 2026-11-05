package metadata

func manualPublicationSchemas() []SchemaDefinition {
	text := func(n, g string) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(4096)}
	}
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/manual-publication-draft-request", phase5ID("bindingId", "BindingID"), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey"), phase5Digest("reasonDigest", "ReasonDigest")),
		phase5Schema("vegastack-labs.dev/manual-publication-binding", phase5ID("bindingId", "BindingID"), text("registryOrigin", "RegistryOrigin"), text("repository", "Repository"), phase5ID("referenceId", "ReferenceID"), phase5ID("materialVersion", "MaterialVersion"), text("candidatePath", "CandidatePath"), phase5Digest("candidateDigest", "CandidateDigest"), text("trustPolicyPath", "TrustPolicyPath"), phase5Digest("trustPolicyDigest", "TrustPolicyDigest"), phase5Digest("imageDigest", "ImageDigest")),
	}
}
func manualPublicationEndpoints() []EndpointDefinition {
	e := phase5Endpoint("api.v1.artifact.publications.drafts.create", "POST", "/api/v1/artifacts/publications/drafts", "vegastack-labs.dev/manual-publication-draft-request", declarationRevisionSchemaID, false)
	e.OwnerPhase = "9"
	e.Availability = AvailabilityAvailable
	return []EndpointDefinition{e}
}
func manualPublicationCommands() []CommandDefinition {
	c := phase4OperatorCommand([]string{"artifact", "publication", "draft"}, "Draft verified manual image publication for exact human acknowledgement.", "vegastack-labs.dev/manual-publication-draft-request", declarationRevisionSchemaID, RiskMutation, []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected operator profile."}, {Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one exact publication draft request."}}, []string{"artifact", "publication", "draft", "--config", "fixture/client.json", "--file", "fixture/publication.json", "--output", "json"})
	c.OwnerPhase = "9"
	return []CommandDefinition{c}
}
