package metadata

const (
	contractExtensionSchemaID       = "vegastack-labs.dev/contract-extension"
	declarationOperationSchemaID    = "vegastack-labs.dev/declaration-operation"
	declarationRevisionRequestID    = "vegastack-labs.dev/declaration-revision-request"
	planBindingSchemaID             = "vegastack-labs.dev/plan-binding"
	planOperationSchemaID           = "vegastack-labs.dev/plan-operation"
	planCreateRequestSchemaID       = "vegastack-labs.dev/plan-create-request"
	planReferenceRequestSchemaID    = "vegastack-labs.dev/plan-reference-request"
	acknowledgementRequestSchemaID  = "vegastack-labs.dev/acknowledgement-request"
	runStepSchemaID                 = "vegastack-labs.dev/run-step"
	runReferenceRequestSchemaID     = "vegastack-labs.dev/run-reference-request"
	executorClaimRequestSchemaID    = "vegastack-labs.dev/executor-claim-request"
	executorRenewRequestSchemaID    = "vegastack-labs.dev/executor-renew-request"
	executionReceiptRequestSchemaID = "vegastack-labs.dev/execution-receipt-request"
)

var phase4RunStates = []string{"cancelled", "failed", "interrupted", "partial", "queued", "running", "succeeded"}

func phase4Endpoints() []EndpointDefinition {
	return []EndpointDefinition{
		phase4Endpoint("api.v1.declarations.revise", "POST", "/api/v1/declarations", declarationRevisionRequestID, declarationRevisionSchemaID),
		phase4Endpoint("api.v1.declarations.get", "GET", "/api/v1/declarations/{declarationId}/revisions/{revision}", "", declarationRevisionSchemaID),
		phase4Endpoint("api.v1.plans.create", "POST", "/api/v1/plans", planCreateRequestSchemaID, planSchemaID),
		phase4Endpoint("api.v1.plans.get", "GET", "/api/v1/plans/{planId}", "", planSchemaID),
		phase4Endpoint("api.v1.plans.acknowledgements.create", "POST", "/api/v1/plans/{planId}/acknowledgements", acknowledgementRequestSchemaID, acknowledgementSchemaID),
		phase4Endpoint("api.v1.plans.execute", "POST", "/api/v1/plans/{planId}/execute", planReferenceRequestSchemaID, runSchemaID),
		phase4Endpoint("api.v1.runs.get", "GET", "/api/v1/runs/{runId}", "", runSchemaID),
		phase4Endpoint("api.v1.runs.cancel", "POST", "/api/v1/runs/{runId}/cancel", runReferenceRequestSchemaID, runSchemaID),
		phase4Endpoint("api.v1.runs.resume", "POST", "/api/v1/runs/{runId}/resume", runReferenceRequestSchemaID, runSchemaID),
		phase4Endpoint("api.v1.executor-leases.claim", "POST", "/api/v1/executor-leases/claim", executorClaimRequestSchemaID, executorLeaseSchemaID),
		phase4Endpoint("api.v1.executor-leases.renew", "POST", "/api/v1/executor-leases/{leaseId}/renew", executorRenewRequestSchemaID, executorLeaseSchemaID),
		phase4Endpoint("api.v1.execution-receipts.create", "POST", "/api/v1/execution-receipts", executionReceiptRequestSchemaID, executionReceiptSchemaID),
	}
}

func phase4Endpoint(id, method, path, request, data string) EndpointDefinition {
	return EndpointDefinition{ID: id, Method: method, Path: path, Availability: AvailabilityPlanned, OwnerPhase: "4", RequestSchema: request, DataSchema: data, Stream: StreamFinite}
}

func phase4Schemas() []SchemaDefinition {
	id := func(name, goName string) FieldDefinition {
		return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueString, Required: true, Pattern: `^[a-z][a-z0-9._:-]{0,127}$`}
	}
	digest := func(name, goName string) FieldDefinition {
		return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueString, Required: true, Pattern: `^sha256:[a-f0-9]{64}$`}
	}
	version := func(name, goName string) FieldDefinition {
		return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueString, Required: true, Pattern: `^1\.[0-9]+\.[0-9]+$`}
	}
	timestamp := func(name, goName string) FieldDefinition {
		return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueString, Required: true, Pattern: `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`}
	}
	nonnegative := func(name, goName string) FieldDefinition {
		return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)}
	}
	positive := func(name, goName string) FieldDefinition {
		return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueInteger, Required: true, Minimum: int64Pointer(1)}
	}
	extensions := FieldDefinition{JSONName: "extensions", GoName: "Extensions", Kind: ValueArray, Required: true, ItemRef: contractExtensionSchemaID, MaxItems: intPointer(64)}
	contract := func(schema string, fields ...FieldDefinition) []FieldDefinition {
		return append([]FieldDefinition{{JSONName: "schema", GoName: "Schema", Kind: ValueString, Required: true, Enum: []string{schema}}, version("schemaVersion", "SchemaVersion")}, fields...)
	}
	operationFields := func(withExecutor bool) []FieldDefinition {
		fields := []FieldDefinition{positive("sequence", "Sequence"), id("operationId", "OperationID"), id("operationType", "OperationType"), id("adapterId", "AdapterID")}
		if withExecutor {
			fields = append(fields, id("executorId", "ExecutorID"))
		}
		return append(fields, id("targetId", "TargetID"), digest("inputDigest", "InputDigest"), digest("artifactDigest", "ArtifactDigest"), FieldDefinition{JSONName: "idempotent", GoName: "Idempotent", Kind: ValueBoolean, Required: true})
	}
	ackRequestFields := append(acknowledgementFields(id, digest, nonnegative, timestamp), extensions)
	ackFields := append(acknowledgementFields(id, digest, nonnegative, timestamp), FieldDefinition{JSONName: "status", GoName: "Status", Kind: ValueString, Required: true, Enum: []string{"approved", "expired", "pending", "rejected"}}, timestamp("createdAt", "CreatedAt"), extensions)
	leaseFields := append(leaseReceiptBinding(id, digest, nonnegative), timestamp("claimedAt", "ClaimedAt"), timestamp("renewAfter", "RenewAfter"), timestamp("leaseExpiresAt", "LeaseExpiresAt"), FieldDefinition{JSONName: "status", GoName: "Status", Kind: ValueString, Required: true, Enum: []string{"active", "expired", "reconciliation-required", "released"}}, extensions)
	receiptFields := append(leaseReceiptBinding(id, digest, nonnegative), id("receiptId", "ReceiptID"), FieldDefinition{JSONName: "status", GoName: "Status", Kind: ValueString, Required: true, Enum: []string{"failed", "partial", "succeeded", "unknown"}}, digest("resultDigest", "ResultDigest"), timestamp("recordedAt", "RecordedAt"), extensions)

	return []SchemaDefinition{
		{ID: contractExtensionSchemaID, Version: "1.0.0", Fields: []FieldDefinition{{JSONName: "name", GoName: "Name", Kind: ValueString, Required: true, Pattern: `^x-[a-z][a-z0-9.-]{0,62}$`}, digest("valueDigest", "ValueDigest")}},
		{ID: declarationOperationSchemaID, Version: "1.0.0", Fields: operationFields(false)},
		{ID: declarationRevisionRequestID, Version: "1.0.0", ArtifactPath: schemaPath(declarationRevisionRequestID), Fields: contract(declarationRevisionRequestID, id("declarationId", "DeclarationID"), id("declarationType", "DeclarationType"), positive("expectedRevision", "ExpectedRevision"), nonnegative("expectedStateRevision", "ExpectedStateRevision"), nonnegative("recoveryEpoch", "RecoveryEpoch"), FieldDefinition{JSONName: "operations", GoName: "Operations", Kind: ValueArray, Required: true, ItemRef: declarationOperationSchemaID, MinItems: intPointer(1), MaxItems: intPointer(256)}, digest("reasonDigest", "ReasonDigest"), extensions)},
		{ID: declarationRevisionSchemaID, Version: "1.0.0", ArtifactPath: schemaPath(declarationRevisionSchemaID), Fields: contract(declarationRevisionSchemaID, id("declarationId", "DeclarationID"), id("declarationType", "DeclarationType"), positive("revision", "Revision"), nonnegative("stateRevision", "StateRevision"), nonnegative("recoveryEpoch", "RecoveryEpoch"), digest("contentDigest", "ContentDigest"), FieldDefinition{JSONName: "status", GoName: "Status", Kind: ValueString, Required: true, Enum: []string{"committed", "draft", "superseded"}}, FieldDefinition{JSONName: "operations", GoName: "Operations", Kind: ValueArray, Required: true, ItemRef: declarationOperationSchemaID, MinItems: intPointer(1), MaxItems: intPointer(256)}, timestamp("createdAt", "CreatedAt"), id("createdBy", "CreatedBy"), id("agentSessionId", "AgentSessionID"), extensions)},
		{ID: planBindingSchemaID, Version: "1.0.0", Fields: []FieldDefinition{nonnegative("recoveryEpoch", "RecoveryEpoch"), nonnegative("priorStateRevision", "PriorStateRevision"), positive("stateRevision", "StateRevision"), positive("declarationRevision", "DeclarationRevision"), digest("observationFingerprint", "ObservationFingerprint"), digest("targetDigest", "TargetDigest"), digest("reasonDigest", "ReasonDigest"), version("policyVersion", "PolicyVersion"), version("toolVersion", "ToolVersion"), version("contractVersion", "ContractVersion")}},
		{ID: planOperationSchemaID, Version: "1.0.0", Fields: operationFields(true)},
		{ID: planCreateRequestSchemaID, Version: "1.0.0", ArtifactPath: schemaPath(planCreateRequestSchemaID), Fields: contract(planCreateRequestSchemaID, id("declarationId", "DeclarationID"), positive("declarationRevision", "DeclarationRevision"), nonnegative("expectedStateRevision", "ExpectedStateRevision"), nonnegative("recoveryEpoch", "RecoveryEpoch"), digest("observationFingerprint", "ObservationFingerprint"), id("idempotencyKey", "IdempotencyKey"), extensions)},
		{ID: planReferenceRequestSchemaID, Version: "1.0.0", ArtifactPath: schemaPath(planReferenceRequestSchemaID), Fields: contract(planReferenceRequestSchemaID, id("planId", "PlanID"), digest("planDigest", "PlanDigest"), nonnegative("recoveryEpoch", "RecoveryEpoch"), id("idempotencyKey", "IdempotencyKey"), extensions)},
		{ID: planSchemaID, Version: "1.0.0", ArtifactPath: schemaPath(planSchemaID), Fields: contract(planSchemaID, id("planId", "PlanID"), digest("planDigest", "PlanDigest"), id("declarationId", "DeclarationID"), FieldDefinition{JSONName: "binding", GoName: "Binding", Kind: ValueObject, Required: true, Ref: planBindingSchemaID}, FieldDefinition{JSONName: "operations", GoName: "Operations", Kind: ValueArray, Required: true, ItemRef: planOperationSchemaID, MinItems: intPointer(1), MaxItems: intPointer(256)}, FieldDefinition{JSONName: "risk", GoName: "Risk", Kind: ValueString, Required: true, Enum: []string{"control-plane", "destructive", "infrastructure", "production-like", "routine"}}, FieldDefinition{JSONName: "authorizationBranch", GoName: "AuthorizationBranch", Kind: ValueString, Required: true, Enum: []string{"human", "preauthorized"}}, timestamp("createdAt", "CreatedAt"), timestamp("expiresAt", "ExpiresAt"), digest("readableDigest", "ReadableDigest"), extensions)},
		{ID: authorizationDecisionSchemaID, Version: "1.0.0", ArtifactPath: schemaPath(authorizationDecisionSchemaID), Fields: contract(authorizationDecisionSchemaID, id("decisionId", "DecisionID"), id("principalId", "PrincipalID"), id("action", "Action"), id("targetId", "TargetID"), FieldDefinition{JSONName: "allowed", GoName: "Allowed", Kind: ValueBoolean, Required: true}, FieldDefinition{JSONName: "branch", GoName: "Branch", Kind: ValueString, Required: true, Nullable: true, Enum: []string{"human", "preauthorized"}}, id("reasonCode", "ReasonCode"), nonnegative("grantRevision", "GrantRevision"), nonnegative("recoveryEpoch", "RecoveryEpoch"), digest("planDigest", "PlanDigest"), timestamp("decidedAt", "DecidedAt"), extensions)},
		{ID: acknowledgementRequestSchemaID, Version: "1.0.0", ArtifactPath: schemaPath(acknowledgementRequestSchemaID), Fields: contract(acknowledgementRequestSchemaID, ackRequestFields...)},
		{ID: acknowledgementSchemaID, Version: "1.0.0", ArtifactPath: schemaPath(acknowledgementSchemaID), Fields: contract(acknowledgementSchemaID, ackFields...)},
		{ID: runStepSchemaID, Version: "1.0.0", Fields: append(operationFields(true), id("stepId", "StepID"), FieldDefinition{JSONName: "status", GoName: "Status", Kind: ValueString, Required: true, Enum: phase4RunStates}, FieldDefinition{JSONName: "effectState", GoName: "EffectState", Kind: ValueString, Required: true, Enum: []string{"effect-unknown", "intent-recorded", "not-started", "receipt-recorded", "verified"}})},
		{ID: runReferenceRequestSchemaID, Version: "1.0.0", ArtifactPath: schemaPath(runReferenceRequestSchemaID), Fields: contract(runReferenceRequestSchemaID, id("runId", "RunID"), id("idempotencyKey", "IdempotencyKey"), nonnegative("recoveryEpoch", "RecoveryEpoch"), extensions)},
		{ID: runSchemaID, Version: "1.0.0", ArtifactPath: schemaPath(runSchemaID), Fields: contract(runSchemaID, id("runId", "RunID"), id("planId", "PlanID"), digest("planDigest", "PlanDigest"), FieldDefinition{JSONName: "status", GoName: "Status", Kind: ValueString, Required: true, Enum: phase4RunStates}, FieldDefinition{JSONName: "steps", GoName: "Steps", Kind: ValueArray, Required: true, ItemRef: runStepSchemaID, MaxItems: intPointer(256)}, FieldDefinition{JSONName: "cancellationRequested", GoName: "CancellationRequested", Kind: ValueBoolean, Required: true}, FieldDefinition{JSONName: "rollbackStatus", GoName: "RollbackStatus", Kind: ValueString, Required: true, Enum: []string{"not-requested", "required", "separate-plan"}}, nonnegative("stateRevision", "StateRevision"), nonnegative("recoveryEpoch", "RecoveryEpoch"), timestamp("createdAt", "CreatedAt"), timestamp("updatedAt", "UpdatedAt"), extensions)},
		{ID: executorClaimRequestSchemaID, Version: "1.0.0", ArtifactPath: schemaPath(executorClaimRequestSchemaID), Fields: contract(executorClaimRequestSchemaID, id("executorId", "ExecutorID"), id("principalId", "PrincipalID"), id("adapterId", "AdapterID"), nonnegative("recoveryEpoch", "RecoveryEpoch"), digest("nonceDigest", "NonceDigest"), extensions)},
		{ID: executorRenewRequestSchemaID, Version: "1.0.0", ArtifactPath: schemaPath(executorRenewRequestSchemaID), Fields: contract(executorRenewRequestSchemaID, id("leaseId", "LeaseID"), digest("bindingDigest", "BindingDigest"), digest("nonceDigest", "NonceDigest"), nonnegative("recoveryEpoch", "RecoveryEpoch"), extensions)},
		{ID: executorLeaseSchemaID, Version: "1.0.0", ArtifactPath: schemaPath(executorLeaseSchemaID), Fields: contract(executorLeaseSchemaID, leaseFields...)},
		{ID: executionReceiptRequestSchemaID, Version: "1.0.0", ArtifactPath: schemaPath(executionReceiptRequestSchemaID), Fields: contract(executionReceiptRequestSchemaID, FieldDefinition{JSONName: "receipt", GoName: "Receipt", Kind: ValueObject, Required: true, Ref: executionReceiptSchemaID}, digest("expectedBindingDigest", "ExpectedBindingDigest"), extensions)},
		{ID: executionReceiptSchemaID, Version: "1.0.0", ArtifactPath: schemaPath(executionReceiptSchemaID), Fields: contract(executionReceiptSchemaID, receiptFields...)},
	}
}

func schemaPath(identifier string) string {
	return "schemas/v1/" + identifier[len("vegastack-labs.dev/"):] + ".schema.json"
}

func acknowledgementFields(id func(string, string) FieldDefinition, digest func(string, string) FieldDefinition, nonnegative func(string, string) FieldDefinition, timestamp func(string, string) FieldDefinition) []FieldDefinition {
	return []FieldDefinition{id("planId", "PlanID"), digest("planDigest", "PlanDigest"), digest("targetDigest", "TargetDigest"), digest("reasonDigest", "ReasonDigest"), id("humanId", "HumanID"), id("authorityId", "AuthorityID"), digest("nonceDigest", "NonceDigest"), nonnegative("stateRevision", "StateRevision"), nonnegative("recoveryEpoch", "RecoveryEpoch"), timestamp("expiresAt", "ExpiresAt")}
}

func leaseReceiptBinding(id func(string, string) FieldDefinition, digest func(string, string) FieldDefinition, nonnegative func(string, string) FieldDefinition) []FieldDefinition {
	return []FieldDefinition{id("leaseId", "LeaseID"), id("planId", "PlanID"), digest("planDigest", "PlanDigest"), id("runId", "RunID"), id("stepId", "StepID"), id("operationId", "OperationID"), id("executorId", "ExecutorID"), id("adapterId", "AdapterID"), id("targetId", "TargetID"), digest("artifactDigest", "ArtifactDigest"), digest("bindingDigest", "BindingDigest"), digest("nonceDigest", "NonceDigest"), nonnegative("recoveryEpoch", "RecoveryEpoch")}
}
