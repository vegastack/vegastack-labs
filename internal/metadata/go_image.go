package metadata

func goImageCommand() CommandDefinition {
	return CommandDefinition{Path: []string{"release", "build-go-image"}, Summary: "Package a static Linux Go binary into a local scratch OCI image and unsigned packaging statements; no compilation, signing or publication.", Availability: AvailabilityAvailable, OwnerPhase: "9", Risk: RiskReadOnly,
		Flags: append([]FlagDefinition{
			{Name: "--binary", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read the actual static Linux Go binary; embedded clean VCS revision must match."},
			{Name: "--source-uri", Kind: FlagValue, ValueName: "uri", Required: true, Summary: "Record caller-supplied source URI; this is not authenticated source identity."},
			{Name: "--source-revision", Kind: FlagValue, ValueName: "revision", Required: true, Summary: "Require this exact revision in compiler-reported clean VCS metadata."},
			{Name: "--builder-id", Kind: FlagValue, ValueName: "uri", Required: true, Summary: "Record supplied packaging builder URI; no signing identity is inferred."},
			{Name: "--invocation-id", Kind: FlagValue, ValueName: "uri", Required: true, Summary: "Record supplied packaging invocation URI."},
			{Name: "--directory", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Create a new local output directory; existing paths are refused."},
		}, commonFlags()...), ResultSchema: runResultSchemaID, DataSchema: "vegastack-labs.dev/go-image-build-data",
		Examples: []ExampleDefinition{{Summary: "Package a previously compiled binary; output remains unsigned.", Arguments: []string{"release", "build-go-image", "--binary", "build/app", "--source-uri", "https://example.org/application", "--source-revision", "0123456789abcdef0123456789abcdef01234567", "--builder-id", "https://example.org/packager", "--invocation-id", "https://example.org/runs/1", "--directory", "build/image", "--output", "json"}}},
	}
}

func goImageSchema() SchemaDefinition {
	return phase5Schema("vegastack-labs.dev/go-image-build-data", phase5Digest("imageDigest", "ImageDigest"), phase5Enum("signatureStatus", "SignatureStatus", "unsigned"), phase5Enum("inventoryScope", "InventoryScope", "compiled-go-modules-only"), phase5Enum("provenanceScope", "ProvenanceScope", "binary-packaging-only"), phase5Enum("metadataTrust", "MetadataTrust", "caller-and-compiler-reported-unverified"))
}
