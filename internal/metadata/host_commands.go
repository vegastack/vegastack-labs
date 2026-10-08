package metadata

func hostCommands() []CommandDefinition {
	commands := []CommandDefinition{}
	for _, item := range []struct {
		action, summary, request, data string
		risk                           RiskClass
	}{
		{"discover", "Collect an untrusted observation from one activated target.", discoveryRequestID, discoverySubmissionID, RiskReadOnly},
		{"add", "Prepare inert host registration; approval and apply remain separate.", adoptionRequestID, adoptionSubmissionID, RiskMutation},
		{"inspect", "Read a registered host without contacting it.", "", managedHostID, RiskReadOnly},
	} {
		flags := []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected server profile."}}
		args := []string{"node", item.action, "--config", "fixture/server-profile.json"}
		if item.action == "inspect" {
			flags = append(flags, FlagDefinition{Name: "--host-id", Kind: FlagValue, ValueName: "id", Required: true, Summary: "Select one registered host ID."})
			args = append(args, "--host-id", "host-a")
		} else {
			flags = append(flags, FlagDefinition{Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one exact request JSON file (16 KiB max)."})
			args = append(args, "--file", "fixture/node-"+item.action+".json")
		}
		c := phase5GateCommand([]string{"node", item.action}, item.summary, item.request, item.data, item.risk, flags, append(args, "--output", "json"))
		c.OwnerPhase = "6"
		commands = append(commands, c)
	}
	return commands
}
