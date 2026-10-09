package metadata

const (
	hostActionBundleID        = "vegastack-labs.dev/host-action-bundle"
	hostActionEnvelopeID      = "vegastack-labs.dev/host-action-envelope"
	hostActionChallengeID     = "vegastack-labs.dev/host-action-challenge"
	hostActionAuthorizationID = "vegastack-labs.dev/host-action-authorization"
	hostActionResultID        = "vegastack-labs.dev/host-action-result"
	hostActionConsoleID       = "vegastack-labs.dev/host-action-console-confirmation"
	hostActionSubmissionID    = "vegastack-labs.dev/host-action-submission"
	hostActionRequestID       = "vegastack-labs.dev/host-action-request"
)

func hostActionSchemas() []SchemaDefinition {
	action := []FieldDefinition{phase5ID("actionId", "ActionID"), phase5Version("actionVersion", "ActionVersion"), phase5Digest("actionInputDigest", "ActionInputDigest"), discoveryText("actionInput", "ActionInput", 32768)}
	bundle := append([]FieldDefinition{}, action...)
	for _, f := range [][2]string{{"bundleId", "BundleID"}, {"planId", "PlanID"}, {"runId", "RunID"}, {"stepId", "StepID"}, {"leaseId", "LeaseID"}, {"hostId", "HostID"}, {"declarationId", "DeclarationID"}, {"automationPrincipalId", "AutomationPrincipalID"}, {"credentialReferenceId", "CredentialReferenceID"}, {"credentialMaterialVersion", "CredentialMaterialVersion"}} {
		bundle = append(bundle, phase5ID(f[0], f[1]))
	}
	for _, f := range [][2]string{{"planDigest", "PlanDigest"}, {"hostIdentityDigest", "HostIdentityDigest"}, {"consoleConfirmationDigest", "ConsoleConfirmationDigest"}} {
		bundle = append(bundle, phase5Digest(f[0], f[1]))
	}
	bundle = append(bundle, phase5Positive("declarationRevision", "DeclarationRevision"), phase5Positive("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Positive("callerUid", "CallerUID"), phase5Timestamp("issuedAt", "IssuedAt"), phase5Timestamp("expiresAt", "ExpiresAt"))
	request := append([]FieldDefinition{}, action...)
	request = append(request, phase5ID("hostId", "HostID"), phase5Positive("targetRevision", "TargetRevision"), phase5Digest("targetDigest", "TargetDigest"), phase5ID("automationPrincipalId", "AutomationPrincipalID"), phase5Positive("callerUid", "CallerUID"), phase5ID("credentialReferenceId", "CredentialReferenceID"), phase5ID("credentialMaterialVersion", "CredentialMaterialVersion"), discoveryRef("consoleConfirmation", "ConsoleConfirmation", hostActionConsoleID), phase5Positive("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey"))
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/native-restart-selector", phase5ID("priorRunId", "PriorRunID"), phase5ID("priorStepId", "PriorStepID")),
		phase5Schema("vegastack-labs.dev/native-restart-presentation", phase5ID("priorRunId", "PriorRunID"), phase5ID("priorStepId", "PriorStepID"), phase5Digest("pendingDigest", "PendingDigest"), phase5Digest("expectedInvocationDigest", "ExpectedInvocationDigest")),
		phase5Schema("vegastack-labs.dev/host-action-credential-confirmation", phase5Enum("method", "Method", "administrator-verified-console"), phase5Digest("targetDigest", "TargetDigest"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), phase5Positive("targetRevision", "TargetRevision")),
		phase5Schema(hostActionBundleID, bundle...),
		phase5Schema(hostActionEnvelopeID, discoveryRef("bundle", "Bundle", hostActionBundleID), phase5ID("keyId", "KeyID"), discoveryText("signature", "Signature", 88)),
		phase5Schema(hostActionChallengeID, phase5Digest("bundleDigest", "BundleDigest"), discoveryText("nonce", "Nonce", 64), phase5ID("hostId", "HostID"), phase5Timestamp("startedAt", "StartedAt")),
		phase5Schema(hostActionAuthorizationID, phase5Digest("bundleDigest", "BundleDigest"), phase5Digest("challengeDigest", "ChallengeDigest"), phase5ID("keyId", "KeyID"), phase5Timestamp("authorizedAt", "AuthorizedAt"), phase5Timestamp("expiresAt", "ExpiresAt"), phase5Positive("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), discoveryText("signature", "Signature", 88)),
		phase5Schema(hostActionResultID, phase5Digest("bundleDigest", "BundleDigest"), phase5Digest("resultDigest", "ResultDigest"), phase5Enum("status", "Status", "succeeded", "failed", "partial"), FieldDefinition{JSONName: "changed", GoName: "Changed", Kind: ValueBoolean, Required: true}, FieldDefinition{JSONName: "effectObserved", GoName: "EffectObserved", Kind: ValueBoolean, Required: true}, phase5ID("reason", "Reason")),
		phase5Schema(hostActionConsoleID, phase5Enum("method", "Method", "administrator-verified-console"), phase5Digest("targetDigest", "TargetDigest"), phase5Digest("hostIdentityDigest", "HostIdentityDigest")),
		phase5Schema(hostActionRequestID, request...),
		phase5Schema(hostActionSubmissionID, phase5ID("draftId", "DraftID"), phase5ID("declarationId", "DeclarationID"), phase5Digest("contentDigest", "ContentDigest"), phase5Positive("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
	}
}

func hostActionEndpoints() []EndpointDefinition {
	e := phase5Endpoint("api.v1.host-actions.draft", "POST", "/api/v1/host-actions/draft", hostActionRequestID, hostActionSubmissionID, false)
	e.OwnerPhase = "6"
	e.Availability = AvailabilityAvailable
	return []EndpointDefinition{e}
}
