package metadata

func ciEnrollmentEndpoints() []EndpointDefinition {
	out := []EndpointDefinition{
		phase5Endpoint("api.v1.ci.enrollments.drafts.create", "POST", "/api/v1/ci/enrollments/drafts", "vegastack-labs.dev/ci-enrollment-draft-request", declarationRevisionSchemaID, false),
		phase5Endpoint("api.v1.ci.enrollments.list", "GET", "/api/v1/ci/enrollments", "", "vegastack-labs.dev/ci-enrollment-list", true),
		phase5Endpoint("api.v1.ci.enrollments.get", "GET", "/api/v1/ci/enrollments/{enrollmentID}", "", "vegastack-labs.dev/ci-enrollment-record", true),
	}
	for i := range out {
		out[i].OwnerPhase = "9"
		out[i].Availability = AvailabilityAvailable
	}
	out[1].QuerySchema = "vegastack-labs.dev/service-read-query"
	return out
}
func ciEnrollmentCommands() []CommandDefinition {
	var out []CommandDefinition
	for _, a := range []string{"draft", "list", "show"} {
		flags := []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected operator profile."}}
		args := []string{"ci", "enrollment", a, "--config", "fixture/client.json"}
		request, data, risk := "", "vegastack-labs.dev/ci-enrollment-list", RiskReadOnly
		summary := "List CI registrations in current scope; job admission remains unqualified."
		if a == "draft" {
			request = "vegastack-labs.dev/ci-enrollment-draft-request"
			data = declarationRevisionSchemaID
			risk = RiskMutation
			summary = "Draft an inert exact CI enrollment for human-acknowledged apply."
			flags = append(flags, FlagDefinition{Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read an opaque enrollment draft request."})
			args = append(args, "--file", "fixture/ci-enrollment.json")
		}
		if a == "show" {
			data = "vegastack-labs.dev/ci-enrollment-record"
			flags = append(flags, FlagDefinition{Name: "--enrollment-id", Kind: FlagValue, ValueName: "id", Required: true, Summary: "Select one exact CI enrollment."})
			args = append(args, "--enrollment-id", "enrollment-a")
		}
		if a == "list" {
			flags = append(flags, FlagDefinition{Name: "--after", Kind: FlagValue, ValueName: "id", Summary: "Continue after one enrollment ID."}, FlagDefinition{Name: "--limit", Kind: FlagValue, ValueName: "count", Summary: "Return 1 through 100 records (default 50)."})
		}
		c := phase4OperatorCommand([]string{"ci", "enrollment", a}, summary, request, data, risk, flags, append(args, "--output", "json"))
		c.OwnerPhase = "9"
		out = append(out, c)
	}
	return out
}
