package metadata

const ciEnrollmentRequestID = "vegastack-labs.dev/ci-enrollment-request"

func ciEnrollmentSchemas() []SchemaDefinition {
	text := func(n, g string, max int) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(max)}
	}
	ref := func(n, g, id string) FieldDefinition {
		return FieldDefinition{JSONName: n, GoName: g, Kind: ValueObject, Required: true, Ref: id}
	}
	optional := text("nextAfter", "NextAfter", 128)
	optional.Required = false
	optional.OmitEmpty = true
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/ci-enrollment-definition", phase5ID("enrollmentId", "EnrollmentID"), phase5ID("ownerId", "OwnerID"), phase5ID("bindingId", "BindingID"), phase5Digest("bindingDigest", "BindingDigest")),
		phase5Schema("vegastack-labs.dev/ci-enrollment-draft-request", phase5ID("enrollmentId", "EnrollmentID"), phase5ID("bindingId", "BindingID"), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey"), phase5Digest("reasonDigest", "ReasonDigest")),
		phase5Schema(ciEnrollmentRequestID, ref("definition", "Definition", "vegastack-labs.dev/ci-enrollment-definition"), phase5Nonnegative("expectedDeclarationRevision", "ExpectedDeclarationRevision"), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey"), phase5Digest("reasonDigest", "ReasonDigest")),
		phase5Schema("vegastack-labs.dev/ci-enrollment-record", ref("definition", "Definition", "vegastack-labs.dev/ci-enrollment-definition"), phase5Positive("revision", "Revision"), phase5Enum("registrationStatus", "RegistrationStatus", "registered"), phase5Enum("admissionStatus", "AdmissionStatus", "not-qualified"), phase5Timestamp("registeredAt", "RegisteredAt"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema("vegastack-labs.dev/ci-enrollment-list", FieldDefinition{JSONName: "enrollments", GoName: "Enrollments", Kind: ValueArray, Required: true, ItemRef: "vegastack-labs.dev/ci-enrollment-record", MaxItems: intPointer(100)}, optional, phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema("vegastack-labs.dev/ci-enrollment-binding", phase5ID("enrollmentId", "EnrollmentID"), phase5ID("ownerId", "OwnerID"), phase5ID("bindingId", "BindingID"), phase5ID("adapterId", "AdapterID"), text("repositoryId", "RepositoryID", 128), text("repositoryOwnerId", "RepositoryOwnerID", 128), text("repository", "Repository", 256), text("workflowId", "WorkflowID", 128), text("workflowPath", "WorkflowPath", 256), phase5Digest("workflowDigest", "WorkflowDigest"), text("revision", "Revision", 64), text("ref", "Ref", 256), phase5Enum("event", "Event", "push", "workflow_dispatch"), text("jobName", "JobName", 256), text("runnerGroupId", "RunnerGroupID", 128), FieldDefinition{JSONName: "labels", GoName: "Labels", Kind: ValueArray, Required: true, ItemKind: ValueString, MinItems: intPointer(1), MaxItems: intPointer(64)}),
	}
}
