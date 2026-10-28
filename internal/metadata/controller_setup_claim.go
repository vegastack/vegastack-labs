package metadata

func controllerSetupClaimSchemas() []SchemaDefinition {
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/controller-setup-recovery-request", phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema("vegastack-labs.dev/controller-setup-recovery-data", phase5Digest("imageDigest", "ImageDigest"), phase5ID("controllerInstanceId", "ControllerInstanceID"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema("vegastack-labs.dev/controller-setup-claim-request", discoveryRef("reference", "Reference", "vegastack-labs.dev/plan-reference-request"), discoveryText("inputJson", "InputJSON", 32768)),
		phase5Schema("vegastack-labs.dev/controller-setup-claim", discoveryRef("plan", "Plan", "vegastack-labs.dev/plan"), discoveryRef("run", "Run", "vegastack-labs.dev/run"), discoveryRef("lease", "Lease", "vegastack-labs.dev/executor-lease"), discoveryRef("policy", "Policy", controllerSetupPilotPolicyID), discoveryText("inputJson", "InputJSON", 32768), phase5Digest("claimDigest", "ClaimDigest"), phase5Timestamp("expiresAt", "ExpiresAt")),
		phase5Schema("vegastack-labs.dev/controller-setup-receipt-request", phase5Digest("claimDigest", "ClaimDigest"), phase5ID("runId", "RunID"), phase5ID("leaseId", "LeaseID"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Digest("resultDigest", "ResultDigest"), discoveryText("inputJson", "InputJSON", 32768), phase5Enum("status", "Status", "installed-awaiting-native-verification", "partial", "failed")),
	}
}
func controllerSetupClaimEndpoints() []EndpointDefinition {
	r := []EndpointDefinition{phase5Endpoint("api.v1.controller-setup.recovery", "POST", "/api/v1/controller-setup/recovery", "vegastack-labs.dev/controller-setup-recovery-request", "vegastack-labs.dev/controller-setup-recovery-data", true), phase5Endpoint("api.v1.controller-setup.claim", "POST", "/api/v1/controller-setup/claim", "vegastack-labs.dev/controller-setup-claim-request", "vegastack-labs.dev/controller-setup-claim", true), phase5Endpoint("api.v1.controller-setup.receipt", "POST", "/api/v1/controller-setup/receipt", "vegastack-labs.dev/controller-setup-receipt-request", "vegastack-labs.dev/run", true)}
	for i := range r {
		r[i].OwnerPhase = "7"
		r[i].Availability = AvailabilityAvailable
	}
	return r
}
