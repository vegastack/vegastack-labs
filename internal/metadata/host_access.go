package metadata

const accessInputID = "vegastack-labs.dev/debian-access-input"
const accessSequenceID = "vegastack-labs.dev/host-access-sequence"
const accessProbeID = "vegastack-labs.dev/access-probe-input"
const accessMeasurementID = "vegastack-labs.dev/access-measurement"

func accessList(jsonName, goName, ref string, max int) FieldDefinition {
	return FieldDefinition{JSONName: jsonName, GoName: goName, Kind: ValueArray, Required: true, ItemRef: ref, MaxItems: intPointer(max)}
}
func accessStrings(jsonName, goName string, max int) FieldDefinition {
	return FieldDefinition{JSONName: jsonName, GoName: goName, Kind: ValueArray, Required: true, ItemKind: ValueString, MaxItems: intPointer(max), UniqueItems: true}
}
func accessBool(jsonName, goName string) FieldDefinition {
	return FieldDefinition{JSONName: jsonName, GoName: goName, Kind: ValueBoolean, Required: true}
}
func accessRef(jsonName, goName, ref string) FieldDefinition {
	return discoveryRef(jsonName, goName, "vegastack-labs.dev/"+ref)
}
func accessSchemas() []SchemaDefinition {
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/access-confirm-input", phase5ID("hostId", "HostID"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), phase5Digest("profileLockDigest", "ProfileLockDigest"), phase5Digest("rollbackDigest", "RollbackDigest"), phase5ID("applyOperationId", "ApplyOperationID"), phase5Digest("applyDraftDigest", "ApplyDraftDigest"), phase5Digest("applyInputDigest", "ApplyInputDigest"), phase5Digest("probeSpecificationDigest", "ProbeSpecificationDigest")),
		phase5Schema("vegastack-labs.dev/access-verification-evidence", phase5Digest("applyReceiptDigest", "ApplyReceiptDigest"), phase5Digest("rollbackRecordDigest", "RollbackRecordDigest"), phase5Digest("probeResultsDigest", "ProbeResultsDigest"), phase5Digest("sequenceDigest", "SequenceDigest"), phase5Timestamp("expiresAt", "ExpiresAt")),
		phase5Schema("vegastack-labs.dev/access-package", phase5ID("name", "Name"), discoveryText("version", "Version", 128)),
		phase5Schema("vegastack-labs.dev/debian-profile-lock", phase5Digest("imageDigest", "ImageDigest"), phase5Enum("osFamily", "OSFamily", "debian"), discoveryText("osVersion", "OSVersion", 32), phase5Enum("architecture", "Architecture", "amd64"), phase5Digest("packageSourceDigest", "PackageSourceDigest"), accessList("packages", "Packages", "vegastack-labs.dev/access-package", 64), phase5Version("executableVersion", "ExecutableVersion"), discoveryText("ansibleVersion", "AnsibleVersion", 64), phase5Digest("ansibleExecutableDigest", "AnsibleExecutableDigest"), phase5Digest("collectionDigest", "CollectionDigest"), phase5Digest("roleDigest", "RoleDigest"), phase5Enum("backend", "Backend", "iptables-nft")),
		phase5Schema("vegastack-labs.dev/access-account", phase5ID("name", "Name"), phase5Positive("uid", "UID"), phase5Positive("gid", "GID"), discoveryText("home", "Home", 256), phase5Enum("role", "Role", "human", "automation", "service"), accessStrings("publicKeys", "PublicKeys", 8), accessStrings("publicKeyDigests", "PublicKeyDigests", 8)),
		phase5Schema("vegastack-labs.dev/access-service-key", phase5ID("serviceId", "ServiceID"), discoveryText("publicKey", "PublicKey", 2048), phase5Digest("publicKeyDigest", "PublicKeyDigest"), accessStrings("sourcePrefixes", "SourcePrefixes", 64)),
		phase5Schema("vegastack-labs.dev/access-interface", phase5ID("name", "Name"), phase5Positive("index", "Index"), accessStrings("addresses", "Addresses", 16), accessBool("ipv6Enabled", "IPv6Enabled")),
		phase5Schema("vegastack-labs.dev/access-flow", phase5Enum("protocol", "Protocol", "tcp", "udp"), discoveryText("sourcePrefix", "SourcePrefix", 64), discoveryText("destinationPrefix", "DestinationPrefix", 64), phase5Positive("port", "Port"), phase5ID("interface", "Interface")),
		phase5Schema("vegastack-labs.dev/access-owned-state", phase5ID("resourceId", "ResourceID"), phase5Digest("beforeDigest", "BeforeDigest"), phase5Digest("afterDigest", "AfterDigest")),
		phase5Schema("vegastack-labs.dev/access-rollback-specification", phase5ID("hostId", "HostID"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), phase5Digest("profileLockDigest", "ProfileLockDigest"), accessList("ownedState", "OwnedState", "vegastack-labs.dev/access-owned-state", 64), FieldDefinition{JSONName: "deadlineSeconds", GoName: "DeadlineSeconds", Kind: ValueInteger, Required: true, Minimum: int64Pointer(600), Maximum: int64Pointer(600)}, accessStrings("recoverySourcePrefixes", "RecoverySourcePrefixes", 64)),
		phase5Schema("vegastack-labs.dev/rendered-access", phase5Digest("profileLockDigest", "ProfileLockDigest"), phase5Digest("rendererDigest", "RendererDigest"), accessList("accounts", "Accounts", "vegastack-labs.dev/access-account", 32), accessStrings("sshUsers", "SSHUsers", 32), accessStrings("sshSourcePrefixes", "SSHSourcePrefixes", 64), accessStrings("recoverySourcePrefixes", "RecoverySourcePrefixes", 64), accessList("privilegedServiceKeys", "PrivilegedServiceKeys", "vegastack-labs.dev/access-service-key", 8), accessList("interfaces", "Interfaces", "vegastack-labs.dev/access-interface", 16), accessList("hostFlows", "HostFlows", "vegastack-labs.dev/access-flow", 64), accessList("containerFlows", "ContainerFlows", "vegastack-labs.dev/access-flow", 64), phase5Digest("rollbackUnitsDigest", "RollbackUnitsDigest")),
		phase5Schema(accessInputID, phase5ID("hostId", "HostID"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), phase5ID("profileId", "ProfileID"), phase5Digest("profileLockDigest", "ProfileLockDigest"), accessRef("profileLock", "ProfileLock", "debian-profile-lock"), phase5Version("actionVersion", "ActionVersion"), phase5Positive("automationUid", "AutomationUID"), accessList("accounts", "Accounts", "vegastack-labs.dev/access-account", 32), accessStrings("sshUsers", "SSHUsers", 32), accessStrings("sshSourcePrefixes", "SSHSourcePrefixes", 64), accessStrings("recoverySourcePrefixes", "RecoverySourcePrefixes", 64), accessList("privilegedServiceKeys", "PrivilegedServiceKeys", "vegastack-labs.dev/access-service-key", 8), accessList("interfaces", "Interfaces", "vegastack-labs.dev/access-interface", 16), accessList("hostFlows", "HostFlows", "vegastack-labs.dev/access-flow", 64), accessList("containerFlows", "ContainerFlows", "vegastack-labs.dev/access-flow", 64), phase5Digest("rollbackDigest", "RollbackDigest"), accessRef("rollbackSpecification", "RollbackSpecification", "access-rollback-specification"), accessRef("renderedAccess", "RenderedAccess", "rendered-access"), phase5Digest("renderedAccessDigest", "RenderedAccessDigest")),
		phase5Schema("vegastack-labs.dev/access-target-identity", phase5ID("hostId", "HostID"), phase5Digest("identityDigest", "IdentityDigest")),
		phase5Schema("vegastack-labs.dev/host-access-probe-step", phase5ID("operationId", "OperationID"), phase5Enum("kind", "Kind", "local-probe", "source-probe", "collect"), phase5ID("sourceHostId", "SourceHostID"), phase5Digest("sourceIdentityDigest", "SourceIdentityDigest"), phase5Digest("sourceContextDigest", "SourceContextDigest"), phase5Digest("draftDigest", "DraftDigest"), phase5Digest("specificationDigest", "SpecificationDigest")),
		phase5Schema(accessSequenceID, accessList("actions", "Actions", hostActionRequestID, 18), accessList("auxiliaryTargets", "AuxiliaryTargets", "vegastack-labs.dev/access-target-identity", 64), phase5ID("subjectHostId", "SubjectHostID"), phase5Digest("subjectIdentityDigest", "SubjectIdentityDigest"), phase5Digest("profileLockDigest", "ProfileLockDigest"), phase5ID("applyOperationId", "ApplyOperationID"), phase5Digest("applyDraftDigest", "ApplyDraftDigest"), accessList("probeSteps", "ProbeSteps", "vegastack-labs.dev/host-access-probe-step", 16), phase5ID("confirmOperationId", "ConfirmOperationID"), phase5Digest("confirmDraftDigest", "ConfirmDraftDigest"), phase5Digest("specificationDigest", "SpecificationDigest")),
		phase5Schema("vegastack-labs.dev/host-access-probe-request", phase5Enum("kind", "Kind", "local-probe", "source-probe", "collect"), accessRef("request", "Request", "host-action-request")),
		phase5Schema("vegastack-labs.dev/host-access-draft-request", accessRef("subject", "Subject", "host-action-request"), accessRef("input", "Input", "debian-access-input"), accessList("probes", "Probes", "vegastack-labs.dev/host-access-probe-request", 16)),
	}
}
func accessEndpoints() []EndpointDefinition {
	e := phase5Endpoint("api.v1.host-access.draft", "POST", "/api/v1/host-access/draft", "vegastack-labs.dev/host-access-draft-request", hostActionSubmissionID, true)
	e.OwnerPhase = "6"
	e.Availability = AvailabilityAvailable
	return []EndpointDefinition{e}
}
