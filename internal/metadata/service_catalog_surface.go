package metadata

func serviceCatalogEndpoints() []EndpointDefinition {
	endpoints := []EndpointDefinition{
		phase5Endpoint("api.v1.services.import-drafts.create", "POST", "/api/v1/services/import-drafts", "vegastack-labs.dev/service-import-draft-request", declarationRevisionSchemaID, false),
		phase5Endpoint("api.v1.services.list", "GET", "/api/v1/services", "", "vegastack-labs.dev/service-list", true),
		phase5Endpoint("api.v1.services.get", "GET", "/api/v1/services/{serviceID}", "", "vegastack-labs.dev/service-record", true),
		phase5Endpoint("api.v1.services.observation.get", "GET", "/api/v1/services/{serviceID}/observation", "", "vegastack-labs.dev/service-observation", true),
	}
	for i := range endpoints {
		endpoints[i].OwnerPhase = "8"
		endpoints[i].Availability = AvailabilityAvailable
	}
	endpoints[1].QuerySchema = "vegastack-labs.dev/service-read-query"
	return endpoints
}

func serviceCatalogCommands() []CommandDefinition {
	var commands []CommandDefinition
	for _, action := range []string{"list", "show", "observe", "import"} {
		path := []string{"service", action}
		flags := []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected operator profile."}}
		args := []string{"service", action, "--config", "fixture/client.json"}
		request, data, risk := "", "vegastack-labs.dev/service-list", RiskReadOnly
		summary := "List registered services within current read scope."
		switch action {
		case "list":
			flags = append(flags, FlagDefinition{Name: "--after", Kind: FlagValue, ValueName: "id", Summary: "Continue after one service ID."}, FlagDefinition{Name: "--limit", Kind: FlagValue, ValueName: "count", Summary: "Return between 1 and 100 services (default 50)."})
		case "show", "observe":
			flags = append(flags, FlagDefinition{Name: "--service-id", Kind: FlagValue, ValueName: "id", Required: true, Summary: "Select one exact registered service."})
			args = append(args, "--service-id", "service-a")
			data = "vegastack-labs.dev/service-record"
			summary = "Read one registered service; host admission remains unverified."
			if action == "observe" {
				data = "vegastack-labs.dev/service-observation"
				summary = "Read current provider observations for one registered service."
			}
		case "import":
			path = append(path, "draft")
			args = []string{"service", "import", "draft", "--config", "fixture/client.json", "--file", "fixture/service-import.json"}
			flags = append(flags, FlagDefinition{Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one inert service-import draft request."})
			request = "vegastack-labs.dev/service-import-draft-request"
			data = declarationRevisionSchemaID
			risk = RiskMutation
			summary = "Draft a local service registration for exact-plan acknowledgement and apply."
		}
		command := phase4OperatorCommand(path, summary, request, data, risk, flags, append(args, "--output", "json"))
		command.OwnerPhase = "8"
		commands = append(commands, command)
	}
	return commands
}
