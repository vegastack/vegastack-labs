package metadata

func serviceDeploymentEndpoints() []EndpointDefinition {
	endpoints := []EndpointDefinition{
		phase5Endpoint("api.v1.services.deployment-drafts.create", "POST", "/api/v1/services/deployment-drafts", "vegastack-labs.dev/service-deployment-draft-request", declarationRevisionSchemaID, false),
		phase5Endpoint("api.v1.services.deployment.get", "GET", "/api/v1/services/{serviceID}/deployment", "", "vegastack-labs.dev/service-deployment-record", true),
	}
	for i := range endpoints {
		endpoints[i].OwnerPhase = "8"
		endpoints[i].Availability = AvailabilityAvailable
	}
	return endpoints
}
func serviceDeploymentCommands() []CommandDefinition {
	var out []CommandDefinition
	for _, action := range []string{"draft", "show"} {
		flags := []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected operator profile."}}
		args := []string{"service", "deployment", action, "--config", "fixture/client.json"}
		request, data, risk := "", "vegastack-labs.dev/service-deployment-record", RiskReadOnly
		summary := "Read the latest deployment result for one registered service."
		if action == "draft" {
			flags = append(flags, FlagDefinition{Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one inert deployment or rollback draft request."})
			args = append(args, "--file", "fixture/service-deployment.json")
			request = "vegastack-labs.dev/service-deployment-draft-request"
			data = declarationRevisionSchemaID
			risk = RiskMutation
			summary = "Draft an exact service deployment or rollback for human acknowledgement."
		} else {
			flags = append(flags, FlagDefinition{Name: "--service-id", Kind: FlagValue, ValueName: "id", Required: true, Summary: "Select one exact registered service."})
			args = append(args, "--service-id", "service-a")
		}
		c := phase4OperatorCommand([]string{"service", "deployment", action}, summary, request, data, risk, flags, append(args, "--output", "json"))
		c.OwnerPhase = "8"
		out = append(out, c)
	}
	return out
}
