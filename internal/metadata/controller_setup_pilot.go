package metadata

const controllerSetupPilotPolicyID = "vegastack-labs.dev/controller-setup-pilot-policy"

func controllerSetupPilotSchemas() []SchemaDefinition {
	return []SchemaDefinition{
		phase5Schema(controllerSetupPilotPolicyID, phase5ID("hostId", "HostID"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), phase5Digest("controllerMachineIdDigest", "ControllerMachineIDDigest"), phase5ID("controllerInstanceId", "ControllerInstanceID"), phase5ID("appliedProfileId", "AppliedProfileID"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Digest("recoveryImageDigest", "RecoveryImageDigest"), phase5Positive("administratorUid", "AdministratorUID"), phase5Positive("administratorGid", "AdministratorGID"), phase5ID("administratorPrincipalId", "AdministratorPrincipalID"), phase5Positive("serviceUid", "ServiceUID"), phase5Positive("serviceGid", "ServiceGID"), phase5Digest("executableDigest", "ExecutableDigest"), phase5Timestamp("expiresAt", "ExpiresAt")),
		phase5Schema("vegastack-labs.dev/controller-setup-pilot-eligibility", phase5ID("hostId", "HostID"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), phase5Digest("controllerMachineIdDigest", "ControllerMachineIDDigest"), phase5ID("controllerInstanceId", "ControllerInstanceID"), phase5Digest("policyDigest", "PolicyDigest"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Positive("administratorUid", "AdministratorUID"), phase5Positive("administratorGid", "AdministratorGID"), phase5ID("administratorPrincipalId", "AdministratorPrincipalID"), phase5Positive("serviceUid", "ServiceUID"), phase5Positive("serviceGid", "ServiceGID"), phase5Digest("recoveryImageDigest", "RecoveryImageDigest")),
	}
}
