package metadata

const meshChangeID = "vegastack-labs.dev/mesh-change"
const meshDraftID = "vegastack-labs.dev/mesh-draft-request"
const meshSubmissionID = "vegastack-labs.dev/mesh-draft-submission"
const meshStatusID = "vegastack-labs.dev/mesh-status-data"
const meshRouteID = "vegastack-labs.dev/mesh-route"

func meshSchemas() []SchemaDefinition {
	return []SchemaDefinition{
		phase5Schema(meshRouteID, discoveryText("address", "Address", 45)),
		phase5Schema(meshChangeID,
			phase5Enum("mode", "Mode", "foundation", "qualified"), phase5ID("profileId", "ProfileID"), discoveryText("accountId", "AccountID", 32),
			phase5Enum("action", "Action", "import", "profile-routing-update", "gateway-rule-update", "registration-delete"),
			phase5Enum("resourceKind", "ResourceKind", "profile-include", "profile-exclude", "gateway-rule", "registration"),
			discoveryText("resourceId", "ResourceID", 64), phase5ID("ownerId", "OwnerID"), phase5ID("deviceId", "DeviceID"),
			discoveryText("physicalDeviceId", "PhysicalDeviceID", 64), discoveryText("providerUserId", "ProviderUserID", 64),
			phase5Nonnegative("expectedOwnershipRevision", "ExpectedOwnershipRevision"), phase5Digest("beforeDigest", "BeforeDigest"),
			discoveryArray("routes", "Routes", meshRouteID, 128),
			FieldDefinition{JSONName: "affectedIdentityDigests", GoName: "AffectedIdentityDigests", Kind: ValueArray, Required: true, ItemKind: ValueString, MinItems: intPointer(1), MaxItems: intPointer(128)},
			discoveryText("meshCidr", "MeshCIDR", 45), discoveryText("ruleName", "RuleName", 128),
			phase5Enum("ruleAction", "RuleAction", "allow", "block"), discoveryText("traffic", "Traffic", 2048), discoveryText("ruleIdentity", "RuleIdentity", 2048),
			phase5Nonnegative("precedence", "Precedence"), phase5Bool("enabled", "Enabled"),
			phase5ID("observationReferenceId", "ObservationReferenceID"), phase5ID("mutationReferenceId", "MutationReferenceID")),
		phase5Schema(meshDraftID, discoveryRef("change", "Change", meshChangeID), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey")),
		phase5Schema(meshSubmissionID, phase5ID("draftId", "DraftID"), phase5ID("declarationId", "DeclarationID"), phase5Digest("contentDigest", "ContentDigest"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema(meshStatusID, phase5ID("profileId", "ProfileID"), phase5Enum("status", "Status", "unknown", "unavailable", "observed", "partial"), phase5ID("reason", "Reason"), phase5Digest("observationDigest", "ObservationDigest"), FieldDefinition{JSONName: "observedAt", GoName: "ObservedAt", Kind: ValueString, OmitEmpty: true, Pattern: `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`}, phase5Nonnegative("ownershipRevision", "OwnershipRevision"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
	}
}
func meshEndpoints() []EndpointDefinition {
	r := []EndpointDefinition{phase5Endpoint("api.v1.network.mesh.observe", "POST", "/api/v1/network/mesh/observe", meshDraftID, meshStatusID, true), phase5Endpoint("api.v1.network.mesh.draft", "POST", "/api/v1/network/mesh/draft", meshDraftID, meshSubmissionID, true), phase5Endpoint("api.v1.network.mesh.status", "GET", "/api/v1/network/mesh/{profileID}", "", meshStatusID, true)}
	for i := range r {
		r[i].OwnerPhase = "7"
		r[i].Availability = AvailabilityAvailable
	}
	return r
}
func meshCommands() []CommandDefinition {
	r := []CommandDefinition{}
	for _, action := range []string{"status", "draft", "observe"} {
		flags := []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected operator profile."}}
		args := []string{"network", "mesh", action, "--config", "fixture/client.json"}
		req, data, risk := "", meshStatusID, RiskReadOnly
		if action == "draft" || action == "observe" {
			req, data, risk = meshDraftID, meshSubmissionID, RiskMutation
			if action == "observe" {
				data, risk = meshStatusID, RiskReadOnly
			}
			flags = append(flags, FlagDefinition{Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one inert Mesh request."})
			args = append(args, "--file", "fixture/mesh.json")
		} else {
			flags = append(flags, FlagDefinition{Name: "--profile-id", Kind: FlagValue, ValueName: "id", Required: true, Summary: "Select an owned Mesh profile."})
			args = append(args, "--profile-id", "mesh-pilot")
		}
		c := phase5GateCommand([]string{"network", "mesh", action}, "Inspect or prepare an owned Mesh change; live gates remain required.", req, data, risk, flags, args)
		c.OwnerPhase = "7"
		r = append(r, c)
	}
	return r
}
