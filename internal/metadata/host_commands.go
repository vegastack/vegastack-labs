package metadata

import "strings"

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

	for _, item := range []struct{ path, summary, request, data string }{
		{"node target prepare", "Prepare an inert discovery target draft.", discoveryDraftID, discoveryDraftSubmissionID},
		{"node action prepare", "Prepare an inert typed host action draft.", hostActionRequestID, hostActionSubmissionID},
		{"node access prepare", "Prepare an inert access policy and probe sequence.", "vegastack-labs.dev/host-access-draft-request", hostActionSubmissionID},
		{"node replacement prepare", "Prepare an inert exact host replacement continuation.", hostReplacementRequestID, "vegastack-labs.dev/host-replacement-submission"},
		{"node replacement inspect", "Read the durable replacement stage and safe next action.", "", "vegastack-labs.dev/host-replacement-state"},
		{"node observation inspect", "Read an existing discovery observation without contacting the host.", "", discoveryObservationID},
	} {
		path := strings.Split(item.path, " ")
		flags := []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected server profile."}}
		args := append(append([]string{}, path...), "--config", "fixture/server-profile.json")
		risk := RiskMutation
		if item.request == "" {
			risk = RiskReadOnly
			idFlag, example := "--observation-id", "observation-a"
			if item.path == "node replacement inspect" {
				idFlag, example = "--replacement-id", "replacement-a"
			}
			flags = append(flags, FlagDefinition{Name: idFlag, Kind: FlagValue, ValueName: "id", Required: true, Summary: "Select one saved lifecycle record."})
			args = append(args, idFlag, example)
		} else {
			flags = append(flags, FlagDefinition{Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one bounded typed request JSON file."})
			args = append(args, "--file", "fixture/host-request.json")
		}
		c := phase5GateCommand(path, item.summary, item.request, item.data, risk, flags, append(args, "--output", "json"))
		c.OwnerPhase = "6"
		commands = append(commands, c)
	}
	return commands
}
