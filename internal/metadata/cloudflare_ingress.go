package metadata

const ingressChangeID = "vegastack-labs.dev/ingress-change"
const ingressDraftID = "vegastack-labs.dev/ingress-draft-request"
const ingressSubmissionID = "vegastack-labs.dev/ingress-draft-submission"
const ingressStatusID = "vegastack-labs.dev/ingress-status-data"
const ingressConnectorID = "vegastack-labs.dev/ingress-connector-target"
const ingressRolloutID = "vegastack-labs.dev/ingress-rollout-evidence-request"

const ingressPilotPolicyID = "vegastack-labs.dev/ingress-controller-read-pilot"
const ingressPilotRequestID = "vegastack-labs.dev/ingress-pilot-evidence-request"

func ingressEmptyText(j, g string, max int) FieldDefinition {
	f := discoveryText(j, g, max)
	f.MinLength = intPointer(0)
	return f
}

func ingressSchemas() []SchemaDefinition {
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/ingress-bootstrap", discoveryText("name", "Name", 128), discoveryText("allowedEmail", "AllowedEmail", 254), nativeSetupOptionalText("originCaPool", "OriginCAPool", 128), FieldDefinition{JSONName: "sourceRunIds", GoName: "SourceRunIDs", Kind: ValueArray, Required: true, ItemKind: ValueString, MaxItems: intPointer(8)}),
		phase5Schema("vegastack-labs.dev/ingress-bootstrap-policy", discoveryRef("change", "Change", ingressChangeID), phase5ID("controllerHostId", "ControllerHostID"), phase5Digest("controllerIdentityDigest", "ControllerIdentityDigest"), phase5Digest("controllerMachineIdDigest", "ControllerMachineIDDigest"), phase5ID("controllerInstanceId", "ControllerInstanceID"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema(ingressPilotPolicyID, discoveryRef("change", "Change", ingressChangeID), phase5ID("controllerHostId", "ControllerHostID"), phase5Digest("controllerIdentityDigest", "ControllerIdentityDigest"), phase5Digest("controllerMachineIdDigest", "ControllerMachineIDDigest"), phase5ID("controllerInstanceId", "ControllerInstanceID"), discoveryRef("identityBinding", "IdentityBinding", "vegastack-labs.dev/browser-identity-binding-change"), phase5Digest("identityBindingDigest", "IdentityBindingDigest"), phase5Digest("identityProfileDigest", "IdentityProfileDigest"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema(ingressPilotRequestID, discoveryRef("request", "Request", ingressDraftID), phase5Enum("gateId", "GateID", "platform-safety", "ingress.controller-read-pilot", "G-016"), phase5ID("evidenceId", "EvidenceID")),
		phase5Schema(ingressConnectorID, ingressEmptyText("connectorId", "ConnectorID", 36), phase5ID("hostId", "HostID"), phase5Digest("identityDigest", "IdentityDigest")),
		phase5Schema(ingressChangeID, phase5ID("profileId", "ProfileID"), discoveryText("accountId", "AccountID", 32), discoveryText("zoneId", "ZoneID", 32), ingressEmptyText("tunnelId", "TunnelID", 36),
			phase5Enum("action", "Action", "import", "tunnel-config-update", "access-policy-update", "dns-record-update", "connector-disconnect", "token-rotate", "bootstrap-tunnel", "bootstrap-group", "bootstrap-app", "bootstrap-policy", "bootstrap-seed", "bootstrap-cutover"), phase5Enum("resourceKind", "ResourceKind", "tunnel-configuration", "access-policy", "dns-record", "connector", "tunnel-token", "access-group", "access-application"), ingressEmptyText("resourceId", "ResourceID", 64), phase5ID("ownerId", "OwnerID"), phase5ID("deviceId", "DeviceID"), phase5Nonnegative("expectedOwnershipRevision", "ExpectedOwnershipRevision"), phase5Digest("beforeDigest", "BeforeDigest"),
			discoveryText("hostname", "Hostname", 253), discoveryText("originService", "OriginService", 256), discoveryText("originServerName", "OriginServerName", 253), phase5Digest("originIdentityDigest", "OriginIdentityDigest"), ingressEmptyText("accessAppId", "AccessAppID", 36), ingressEmptyText("accessPolicyId", "AccessPolicyID", 36), discoveryText("dnsRecordId", "DNSRecordID", 64), ingressEmptyText("connectorId", "ConnectorID", 36),
			discoveryText("policyName", "PolicyName", 128), phase5Nonnegative("precedence", "Precedence"), FieldDefinition{JSONName: "allowedGroupIds", GoName: "AllowedGroupIDs", Kind: ValueArray, Required: true, ItemKind: ValueString, MaxItems: intPointer(128)}, discoveryArray("connectors", "Connectors", ingressConnectorID, 16), phase5ID("observationReferenceId", "ObservationReferenceID"), phase5ID("mutationReferenceId", "MutationReferenceID"), phase5ID("replacementReferenceId", "ReplacementReferenceID"), nativeOptionalRef("bootstrap", "Bootstrap", "ingress-bootstrap")),
		phase5Schema(ingressDraftID, discoveryRef("change", "Change", ingressChangeID), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey")),
		phase5Schema(ingressSubmissionID, phase5ID("draftId", "DraftID"), phase5ID("declarationId", "DeclarationID"), phase5Digest("contentDigest", "ContentDigest"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema(ingressStatusID, nativeSetupOptionalText("resourceId", "ResourceID", 64), nativeSetupOptionalText("resourceKind", "ResourceKind", 64), nativeSetupOptionalText("runId", "RunID", 128), phase5ID("profileId", "ProfileID"), phase5Enum("status", "Status", "unknown", "unavailable", "observed", "partial"), phase5ID("reason", "Reason"), phase5Digest("observationDigest", "ObservationDigest"), FieldDefinition{JSONName: "observedAt", GoName: "ObservedAt", Kind: ValueString, OmitEmpty: true, Pattern: `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`}, phase5Nonnegative("ownershipRevision", "OwnershipRevision"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Enum("rotationStage", "RotationStage", "not-requested", "provider-rotated", "connector-update-required", "verification-pending", "partial", "uncertain"), phase5Enum("connectivity", "Connectivity", "unknown", "unavailable"), phase5Enum("originIsolation", "OriginIsolation", "unknown", "unavailable")),
		phase5Schema(ingressRolloutID, phase5ID("profileId", "ProfileID"), phase5ID("rotationRunId", "RotationRunID"), phase5ID("materialVersion", "MaterialVersion"), discoveryArray("connectors", "Connectors", ingressConnectorID, 16), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey")),
	}
}
func ingressEndpoints() []EndpointDefinition {
	r := []EndpointDefinition{phase5Endpoint("api.v1.network.ingress.pilot-evidence", "POST", "/api/v1/network/ingress/pilot-evidence", ingressPilotRequestID, gateEvidenceSubmissionSchemaID, true), phase5Endpoint("api.v1.network.ingress.draft", "POST", "/api/v1/network/ingress/draft", ingressDraftID, ingressSubmissionID, true), phase5Endpoint("api.v1.network.ingress.observe", "POST", "/api/v1/network/ingress/observe", ingressDraftID, ingressStatusID, true), phase5Endpoint("api.v1.network.ingress.status", "GET", "/api/v1/network/ingress/{profileID}", "", ingressStatusID, true), phase5Endpoint("api.v1.network.ingress.rollout-evidence", "POST", "/api/v1/network/ingress/rollout-evidence", ingressRolloutID, ingressStatusID, true)}
	for i := range r {
		r[i].OwnerPhase = "7"
		r[i].Availability = AvailabilityAvailable
	}
	return r
}
func ingressCommands() []CommandDefinition {
	r := []CommandDefinition{}
	for _, action := range []string{"status", "observe", "draft", "rollout-evidence", "pilot-evidence"} {
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
			if action == "pilot-evidence" {
				req, data, risk = ingressPilotRequestID, gateEvidenceSubmissionSchemaID, RiskMutation
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
