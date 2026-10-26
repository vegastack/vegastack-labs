package metadata

const ingressChangeID = "vegastack-labs.dev/ingress-change"
const ingressDraftID = "vegastack-labs.dev/ingress-draft-request"
const ingressSubmissionID = "vegastack-labs.dev/ingress-draft-submission"
const ingressStatusID = "vegastack-labs.dev/ingress-status-data"
const ingressConnectorID = "vegastack-labs.dev/ingress-connector-target"
const ingressRolloutID = "vegastack-labs.dev/ingress-rollout-evidence-request"

func ingressSchemas() []SchemaDefinition {
	return []SchemaDefinition{
		phase5Schema(ingressConnectorID, discoveryText("connectorId", "ConnectorID", 36), phase5ID("hostId", "HostID"), phase5Digest("identityDigest", "IdentityDigest")),
		phase5Schema(ingressChangeID, phase5ID("profileId", "ProfileID"), discoveryText("accountId", "AccountID", 32), discoveryText("zoneId", "ZoneID", 32), discoveryText("tunnelId", "TunnelID", 36),
			phase5Enum("action", "Action", "import", "tunnel-config-update", "access-policy-update", "dns-record-update", "connector-disconnect", "token-rotate"), phase5Enum("resourceKind", "ResourceKind", "tunnel-configuration", "access-policy", "dns-record", "connector", "tunnel-token"), discoveryText("resourceId", "ResourceID", 64), phase5ID("ownerId", "OwnerID"), phase5ID("deviceId", "DeviceID"), phase5Nonnegative("expectedOwnershipRevision", "ExpectedOwnershipRevision"), phase5Digest("beforeDigest", "BeforeDigest"),
			discoveryText("hostname", "Hostname", 253), discoveryText("originService", "OriginService", 256), discoveryText("originServerName", "OriginServerName", 253), phase5Digest("originIdentityDigest", "OriginIdentityDigest"), discoveryText("accessAppId", "AccessAppID", 36), discoveryText("accessPolicyId", "AccessPolicyID", 36), discoveryText("dnsRecordId", "DNSRecordID", 64), discoveryText("connectorId", "ConnectorID", 36),
			discoveryText("policyName", "PolicyName", 128), phase5Nonnegative("precedence", "Precedence"), FieldDefinition{JSONName: "allowedGroupIds", GoName: "AllowedGroupIDs", Kind: ValueArray, Required: true, ItemKind: ValueString, MaxItems: intPointer(128)}, discoveryArray("connectors", "Connectors", ingressConnectorID, 16), phase5ID("observationReferenceId", "ObservationReferenceID"), phase5ID("mutationReferenceId", "MutationReferenceID"), phase5ID("replacementReferenceId", "ReplacementReferenceID")),
		phase5Schema(ingressDraftID, discoveryRef("change", "Change", ingressChangeID), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey")),
		phase5Schema(ingressSubmissionID, phase5ID("draftId", "DraftID"), phase5ID("declarationId", "DeclarationID"), phase5Digest("contentDigest", "ContentDigest"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema(ingressStatusID, phase5ID("profileId", "ProfileID"), phase5Enum("status", "Status", "unknown", "unavailable", "observed", "partial"), phase5ID("reason", "Reason"), phase5Digest("observationDigest", "ObservationDigest"), FieldDefinition{JSONName: "observedAt", GoName: "ObservedAt", Kind: ValueString, OmitEmpty: true, Pattern: `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`}, phase5Nonnegative("ownershipRevision", "OwnershipRevision"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Enum("rotationStage", "RotationStage", "not-requested", "provider-rotated", "connector-update-required", "verification-pending", "partial", "uncertain"), phase5Enum("connectivity", "Connectivity", "unknown", "unavailable"), phase5Enum("originIsolation", "OriginIsolation", "unknown", "unavailable")),
		phase5Schema(ingressRolloutID, phase5ID("profileId", "ProfileID"), phase5ID("rotationRunId", "RotationRunID"), phase5ID("materialVersion", "MaterialVersion"), discoveryArray("connectors", "Connectors", ingressConnectorID, 16), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey")),
	}
}
func ingressEndpoints() []EndpointDefinition {
	r := []EndpointDefinition{phase5Endpoint("api.v1.network.ingress.draft", "POST", "/api/v1/network/ingress/draft", ingressDraftID, ingressSubmissionID, true), phase5Endpoint("api.v1.network.ingress.observe", "POST", "/api/v1/network/ingress/observe", ingressDraftID, ingressStatusID, true), phase5Endpoint("api.v1.network.ingress.status", "GET", "/api/v1/network/ingress/{profileID}", "", ingressStatusID, true), phase5Endpoint("api.v1.network.ingress.rollout-evidence", "POST", "/api/v1/network/ingress/rollout-evidence", ingressRolloutID, ingressStatusID, true)}
	for i := range r {
		r[i].OwnerPhase = "7"
		r[i].Availability = AvailabilityAvailable
	}
	return r
}
func ingressCommands() []CommandDefinition {
	r := []CommandDefinition{}
	for _, action := range []string{"status", "observe", "draft", "rollout-evidence"} {
		flags := []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected operator profile."}}
		args := []string{"network", "ingress", action, "--config", "fixture/client.json"}
		req, data, risk := "", ingressStatusID, RiskReadOnly
		if action == "status" {
			flags = append(flags, FlagDefinition{Name: "--profile-id", Kind: FlagValue, ValueName: "id", Required: true, Summary: "Select an owned ingress profile."})
			args = append(args, "--profile-id", "ingress-pilot")
		} else {
			req = ingressDraftID
			if action == "draft" {
				data = ingressSubmissionID
				risk = RiskMutation
			}
			if action == "rollout-evidence" {
				req = ingressRolloutID
			}
			flags = append(flags, FlagDefinition{Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read an exact non-secret typed request."})
			args = append(args, "--file", "fixture/ingress.json")
		}
		c := phase5GateCommand([]string{"network", "ingress", action}, "Inspect or prepare owned ingress; provider rotation alone is incomplete.", req, data, risk, flags, args)
		c.OwnerPhase = "7"
		r = append(r, c)
	}
	return r
}
