package metadata

func serviceConfigurationEndpoints() []EndpointDefinition {
	e := phase5Endpoint("api.v1.services.configuration.get", "GET", "/api/v1/services/{serviceID}/configuration", "", "vegastack-labs.dev/service-configuration-status", true)
	e.OwnerPhase = "8"
	e.Availability = AvailabilityAvailable
	return []EndpointDefinition{e}
}
func serviceConfigurationCommands() []CommandDefinition {
	c := phase4OperatorCommand([]string{"service", "configuration", "show"}, "Inspect service settings and explicit target eligibility.", "", "vegastack-labs.dev/service-configuration-status", RiskReadOnly, []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected operator profile."}, {Name: "--service-id", Kind: FlagValue, ValueName: "id", Required: true, Summary: "Select one exact registered service."}}, []string{"service", "configuration", "show", "--config", "fixture/client.json", "--service-id", "service-a", "--output", "json"})
	c.OwnerPhase = "8"
	return []CommandDefinition{c}
}
