package metadata

const networkEndpointID = "vegastack-labs.dev/network-endpoint"
const networkEndpointRequestID = "vegastack-labs.dev/network-endpoint-request"
const networkDescriptorID = "vegastack-labs.dev/network-connect-descriptor"
const networkResultID = "vegastack-labs.dev/network-connect-result"

func networkConnectSchemas() []SchemaDefinition {
	text := func(n, g string, max int) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(max)}
	}
	return []SchemaDefinition{
		phase5Schema(networkEndpointID, phase5ID("hostId", "HostID"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), phase5ID("targetId", "TargetID"), phase5Positive("targetRevision", "TargetRevision"), text("hostKey", "HostKey", 2048), text("user", "User", 32), text("lanAddress", "LANAddress", 64), phase5Positive("lanPort", "LANPort"), text("meshAddress", "MeshAddress", 64), phase5Positive("meshPort", "MeshPort"), text("markerAddress", "MarkerAddress", 64), phase5Positive("markerPort", "MarkerPort"), text("markerPath", "MarkerPath", 256), phase5Digest("markerCertificateDigest", "MarkerCertificateDigest"), text("markerValue", "MarkerValue", 128), phase5Enum("flow", "Flow", "operator-client-to-host-ssh"), phase5Positive("revision", "Revision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema(networkEndpointRequestID, FieldDefinition{JSONName: "endpoint", GoName: "Endpoint", Kind: ValueObject, Required: true, Ref: networkEndpointID}, phase5Enum("action", "Action", "activate", "revoke"), phase5Nonnegative("expectedEndpointRevision", "ExpectedEndpointRevision"), phase5Nonnegative("expectedDeclarationRevision", "ExpectedDeclarationRevision"), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey"), phase5Digest("reasonDigest", "ReasonDigest")),
		phase5Schema(networkDescriptorID, FieldDefinition{JSONName: "endpoint", GoName: "Endpoint", Kind: ValueObject, Required: true, Ref: networkEndpointID}, phase5Digest("endpointDigest", "EndpointDigest"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Positive("grantRevision", "GrantRevision")),
		phase5Schema(networkResultID, phase5ID("hostId", "HostID"), phase5Enum("path", "Path", "lan", "mesh"), phase5Digest("endpointDigest", "EndpointDigest"), phase5Enum("outcome", "Outcome", "authenticated-and-closed")),
	}
}
func networkConnectCommands() []CommandDefinition {
	draft := authorizationGrantCommand()
	draft.Path = []string{"network", "endpoint", "draft"}
	draft.OwnerPhase = "7"
	draft.RequestSchema = networkEndpointRequestID
	draft.Summary = "Draft one managed-host connection endpoint; acknowledge its exact plan before apply."
	draft.Examples = []ExampleDefinition{{Summary: "Draft an explicit endpoint.", Arguments: []string{"network", "endpoint", "draft", "--config", "fixture/profile.json", "--file", "fixture/endpoint.json", "--output", "json"}}}
	connect := phase4OperatorCommand([]string{"connect"}, "Authenticate and close one pinned managed-node SSH connection; no shell or forwarding.", "", networkResultID, RiskReadOnly, []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected client profile."}, {Name: "--node", Kind: FlagValue, ValueName: "id", Required: true, Summary: "Select one exact registered managed host."}, {Name: "--port", Kind: FlagValue, ValueName: "port", Enum: []string{"22"}, Summary: "Use the declared SSH port 22."}, {Name: "--path", Kind: FlagValue, ValueName: "path", Enum: []string{"auto", "lan", "mesh"}, Summary: "Select auto, LAN or Mesh without changing identity checks."}}, []string{"connect", "--config", "fixture/profile.json", "--node", "synthetic-host", "--port", "22", "--path", "auto", "--output", "json"})
	connect.OwnerPhase = "7"
	return []CommandDefinition{draft, connect}
}
func networkConnectEndpoints() []EndpointDefinition {
	draft := phase5Endpoint("api.v1.network.endpoint-drafts.create", "POST", "/api/v1/network/endpoint-drafts", networkEndpointRequestID, declarationRevisionSchemaID, false)
	draft.Availability = AvailabilityAvailable
	draft.OwnerPhase = "7"
	descriptor := phase5Endpoint("api.v1.hosts.connection-descriptor.get", "GET", "/api/v1/hosts/{hostID}/connection-descriptor", "", networkDescriptorID, false)
	descriptor.Availability = AvailabilityAvailable
	descriptor.OwnerPhase = "7"
	return []EndpointDefinition{draft, descriptor}
}
