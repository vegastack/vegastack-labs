package metadata

func doctorCommand() CommandDefinition {
	command := operatorCommand([]string{"doctor"}, "Diagnose the first failing control-summary invariant without mutation.", "", apiSummaryDataSchemaID, []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read the protected server profile at this explicit path."}}, []string{"doctor", "--config", "fixture/server-profile.json", "--output", "json"})
	command.OwnerPhase = "10"
	return command
}
