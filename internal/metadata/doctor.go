package metadata

func doctorCommand() CommandDefinition {
	command := operatorCommand([]string{"doctor"}, "Diagnose the first failing control-summary invariant without mutation.", "", apiSummaryDataSchemaID, []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read the protected server profile at this explicit path."}}, []string{"doctor", "--config", "fixture/server-profile.json", "--output", "json"})
	command.OwnerPhase = "10"
	return command
}

const controllerPrerequisitesID = "vegastack-labs.dev/controller-prerequisites-data"

func controllerPrerequisitesCommand() CommandDefinition {
	c := operatorCommand([]string{"doctor", "controller-prerequisites"}, "Collect fixed local controller metadata without secrets, writes or admission.", "", controllerPrerequisitesID, []FlagDefinition{{Name: "--expected-machine-id", Kind: FlagValue, ValueName: "id", Required: true, Summary: "Require this exact Linux machine ID before reading controller metadata."}}, []string{"doctor", "controller-prerequisites", "--expected-machine-id", "00000000000000000000000000000001", "--output", "json"})
	c.OwnerPhase = "10"
	return c
}
func controllerPrerequisitesSchemas() []SchemaDefinition {
	fact := phase5Schema("vegastack-labs.dev/controller-prerequisite-fact", phase5Enum("selector", "Selector", "account", "profile", "executable", "state", "runtime", "unit", "custody-policy", "credential-drafts", "tls-certificate"), phase5Enum("state", "State", "present", "missing", "unavailable", "unsafe", "invalid", "disabled"), nativeSetupOptionalText("digest", "Digest", 71), nativeSetupOptionalText("mode", "Mode", 10), nativeSetupOptionalText("uid", "UID", 20), nativeSetupOptionalText("gid", "GID", 20), nativeSetupOptionalText("notAfter", "NotAfter", 40), nativeSetupOptionalText("dnsNames", "DNSNames", 2048))
	return []SchemaDefinition{fact, phase5Schema(controllerPrerequisitesID, phase5Enum("platform", "Platform", "linux", "unsupported"), accessBool("identityMatched", "IdentityMatched"), accessBool("admissionQualified", "AdmissionQualified"), discoveryArray("facts", "Facts", fact.ID, 16))}
}
