package metadata

const (
	gateDefinitionSchemaID             = "vegastack-labs.dev/gate-definition"
	gateEvidenceSchemaID               = "vegastack-labs.dev/gate-evidence"
	gateEvaluationSchemaID             = "vegastack-labs.dev/gate-evaluation"
	credentialReferenceSchemaID        = "vegastack-labs.dev/credential-reference"
	credentialResolutionRecordSchemaID = "vegastack-labs.dev/credential-resolution-record"
	backupPolicySchemaID               = "vegastack-labs.dev/backup-policy"
	backupJobSchemaID                  = "vegastack-labs.dev/backup-job"
	recoveryPointSchemaID              = "vegastack-labs.dev/recovery-point"
	auditCheckpointSchemaID            = "vegastack-labs.dev/audit-checkpoint"
	restoreBindingSchemaID             = "vegastack-labs.dev/restore-binding"
	restoreVerificationSchemaID        = "vegastack-labs.dev/restore-verification"
	scheduledJobPolicySchemaID         = "vegastack-labs.dev/scheduled-job-policy"
	scheduledJobSchemaID               = "vegastack-labs.dev/scheduled-job"
	gateCheckRequestSchemaID           = "vegastack-labs.dev/gate-check-request"
	gateEvidenceRequestSchemaID        = "vegastack-labs.dev/gate-evidence-request"
	gateProfileDraftRequestSchemaID    = "vegastack-labs.dev/gate-profile-draft-request"
	gateProfileDraftSubmissionSchemaID = "vegastack-labs.dev/gate-profile-draft-submission"
	gateEvidenceFactSchemaID           = "vegastack-labs.dev/gate-evidence-fact"
	gateEvidenceCheckSchemaID          = "vegastack-labs.dev/gate-evidence-check"
	gateEvidenceAttachmentSchemaID     = "vegastack-labs.dev/gate-evidence-attachment"
	gateEvidenceBundleSchemaID         = "vegastack-labs.dev/gate-evidence-bundle"
	gateEvidenceSubmissionSchemaID     = "vegastack-labs.dev/gate-evidence-submission"
	gateViewSchemaID                   = "vegastack-labs.dev/gate-view"
	backupRunRequestSchemaID           = "vegastack-labs.dev/backup-run-request"
	backupVerifyRequestSchemaID        = "vegastack-labs.dev/backup-verify-request"
	restoreRequestSchemaID             = "vegastack-labs.dev/restore-request"
	restoreRunRequestSchemaID          = "vegastack-labs.dev/restore-run-request"
	restoreVerifyRequestSchemaID       = "vegastack-labs.dev/restore-verify-request"
	scheduledJobRequestSchemaID        = "vegastack-labs.dev/scheduled-job-request"
	credentialReferenceRequestSchemaID = "vegastack-labs.dev/credential-reference-request"
	credentialImportRequestSchemaID    = "vegastack-labs.dev/credential-import-request"
	credentialImportSubmissionSchemaID = "vegastack-labs.dev/credential-import-submission"
	auditCheckpointRequestSchemaID     = "vegastack-labs.dev/audit-checkpoint-request"
	databaseExportRequestSchemaID      = "vegastack-labs.dev/database-export-request"
	gateListDataSchemaID               = "vegastack-labs.dev/gate-list-data"
	backupStatusDataSchemaID           = "vegastack-labs.dev/backup-status-data"
	auditCheckpointListDataSchemaID    = "vegastack-labs.dev/audit-checkpoint-list-data"
	browserRestoreStatusSchemaID       = "vegastack-labs.dev/browser-restore-status"
	sanitizedExportDataSchemaID        = "vegastack-labs.dev/sanitized-export-data"
)

// Phase 5 metadata describes public shapes. It does not make an evidence
// assertion, resolve a credential, or install a runtime handler.
func phase5Contract(identifier string, fields ...FieldDefinition) []FieldDefinition {
	return append([]FieldDefinition{
		{JSONName: "schema", GoName: "Schema", Kind: ValueString, Required: true, Enum: []string{identifier}},
		{JSONName: "schemaVersion", GoName: "SchemaVersion", Kind: ValueString, Required: true, Enum: []string{"1.0.0"}},
	}, fields...)
}

func phase5Schema(identifier string, fields ...FieldDefinition) SchemaDefinition {
	return SchemaDefinition{ID: identifier, Version: "1.0.0", ArtifactPath: schemaPath(identifier), Fields: phase5Contract(identifier, fields...)}
}

// Gate evidence is a scoped additive revision. Other Phase 5 contracts retain
// their own 1.0.0 sources until their owning issues version them.
func phase5GateSchema(identifier string, fields ...FieldDefinition) SchemaDefinition {
	schema := phase5Schema(identifier, fields...)
	schema.Version = "1.1.0"
	schema.Fields[1].Enum = []string{"1.1.0"}
	return schema
}

func phase5CredentialSchema(identifier string, fields ...FieldDefinition) SchemaDefinition {
	schema := phase5Schema(identifier, fields...)
	schema.Version = "1.1.0"
	schema.Fields[1].Enum = []string{"1.1.0"}
	return schema
}

func phase5ID(name, goName string) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueString, Required: true, Pattern: `^[a-z][a-z0-9._:-]{0,127}$`}
}

func phase5GateID() FieldDefinition {
	return FieldDefinition{JSONName: "gateId", GoName: "GateID", Kind: ValueString, Required: true, Pattern: `^(G-[0-9]{3}|[a-z][a-z0-9._:-]{0,127})$`}
}

func phase5Digest(name, goName string) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueString, Required: true, Pattern: `^sha256:[a-f0-9]{64}$`}
}

func phase5Version(name, goName string) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueString, Required: true, Pattern: `^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`}
}

func phase5Timestamp(name, goName string) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueString, Required: true, Pattern: `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`}
}

func phase5Nonnegative(name, goName string) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)}
}

func phase5Positive(name, goName string) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueInteger, Required: true, Minimum: int64Pointer(1)}
}

func phase5Interval(name, goName string) FieldDefinition {
	field := phase5Positive(name, goName)
	field.Maximum = int64Pointer(604800)
	return field
}

func phase5Bool(name, goName string) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueBoolean, Required: true}
}

func phase5Enum(name, goName string, values ...string) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueString, Required: true, Enum: values}
}

func phase5IDs(name, goName string, maximum int) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueArray, Required: true, ItemKind: ValueString, MaxItems: intPointer(maximum), UniqueItems: true}
}

func phase5NullableID(name, goName string) FieldDefinition {
	field := phase5ID(name, goName)
	field.Nullable = true
	return field
}

func phase5NullableDigest(name, goName string) FieldDefinition {
	field := phase5Digest(name, goName)
	field.Nullable = true
	return field
}

func phase5NullableTimestamp(name, goName string) FieldDefinition {
	field := phase5Timestamp(name, goName)
	field.Nullable = true
	return field
}

func phase5GateCredentialSchemas() []SchemaDefinition {
	return []SchemaDefinition{
		phase5GateSchema(gateDefinitionSchemaID,
			phase5GateID(), phase5Version("definitionVersion", "DefinitionVersion"),
			phase5Enum("layer", "Layer", "platform", "adapter", "deployment-profile", "site"),
			phase5NullableID("profileId", "ProfileID"), phase5NullableID("capabilityId", "CapabilityID"),
			phase5IDs("subjectKinds", "SubjectKinds", 64),
			phase5Enum("applicability", "Applicability", "always", "capability", "profile", "subject", "deferred"),
			phase5IDs("prerequisiteGateIds", "PrerequisiteGateIDs", 64),
			FieldDefinition{JSONName: "evidenceSchemaId", GoName: "EvidenceSchemaID", Kind: ValueString, Required: true, Pattern: `^[a-z0-9][a-z0-9./-]*$`},
			phase5Version("evaluatorVersion", "EvaluatorVersion"),
			phase5Positive("freshnessSeconds", "FreshnessSeconds"),
			phase5Bool("recoveryEpochBound", "RecoveryEpochBound"),
		),
		phase5GateSchema(gateEvidenceSchemaID,
			phase5ID("evidenceId", "EvidenceID"), phase5GateID(), phase5ID("subjectId", "SubjectID"),
			phase5Version("definitionVersion", "DefinitionVersion"), phase5Version("evaluatorVersion", "EvaluatorVersion"),
			phase5ID("releaseBuildId", "ReleaseBuildID"), phase5Version("toolVersion", "ToolVersion"),
			phase5ID("profileId", "ProfileID"), phase5Version("profileVersion", "ProfileVersion"),
			phase5ID("policyId", "PolicyID"), phase5Version("policyVersion", "PolicyVersion"),
			phase5ID("declarationId", "DeclarationID"), phase5Positive("declarationRevision", "DeclarationRevision"),
			phase5Nonnegative("stateRevision", "StateRevision"),
			phase5Enum("sourceKind", "SourceKind", "fixture", "local", "independent"),
			phase5Enum("proofClass", "ProofClass", "fixture", "live"),
			phase5ID("collectorId", "CollectorID"), phase5ID("humanId", "HumanID"),
			phase5Digest("artifactDigest", "ArtifactDigest"), phase5Digest("bundleDigest", "BundleDigest"),
			phase5Timestamp("observedAt", "ObservedAt"), phase5Timestamp("appliedAt", "AppliedAt"), phase5Timestamp("expiresAt", "ExpiresAt"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5NullableID("supersedesEvidenceId", "SupersedesEvidenceID"),
			phase5NullableID("revokesEvidenceId", "RevokesEvidenceID"),
			phase5Enum("status", "Status", "applied", "revoked"),
		),
		phase5GateSchema(gateEvaluationSchemaID,
			phase5ID("evaluationId", "EvaluationID"), phase5GateID(), phase5ID("subjectId", "SubjectID"),
			phase5Version("definitionVersion", "DefinitionVersion"), phase5Version("evaluatorVersion", "EvaluatorVersion"),
			phase5IDs("evidenceIds", "EvidenceIDs", 64), phase5Timestamp("evaluatedAt", "EvaluatedAt"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5Enum("outcome", "Outcome", "passed", "blocked", "not-applicable", "stale", "unknown"),
			phase5ID("reasonCode", "ReasonCode"),
			phase5Enum("evidenceSource", "EvidenceSource", "none", "fixture", "local", "independent"),
			phase5Bool("readyForInput", "ReadyForInput"),
		),
		phase5GateSchema(gateViewSchemaID,
			FieldDefinition{JSONName: "definition", GoName: "Definition", Kind: ValueObject, Required: true, Ref: gateDefinitionSchemaID},
			FieldDefinition{JSONName: "evaluation", GoName: "Evaluation", Kind: ValueObject, Required: true, Ref: gateEvaluationSchemaID},
			phase5ID("applicabilityReasonCode", "ApplicabilityReasonCode"),
		),
		phase5CredentialSchema(credentialReferenceSchemaID,
			phase5ID("referenceId", "ReferenceID"), phase5ID("consumerId", "ConsumerID"), phase5ID("purposeId", "PurposeID"),
			phase5ID("targetId", "TargetID"), phase5ID("resolverId", "ResolverID"),
			phase5ID("materialVersion", "MaterialVersion"), phase5Digest("fingerprint", "Fingerprint"),
			phase5Enum("status", "Status", "staged", "active", "unavailable", "revoked"),
			phase5Positive("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5NullableTimestamp("activatedAt", "ActivatedAt"), phase5IDs("verifiedConsumerIds", "VerifiedConsumerIDs", 64),
		),
		phase5CredentialSchema(credentialResolutionRecordSchemaID,
			phase5ID("recordId", "RecordID"), phase5ID("referenceId", "ReferenceID"),
			phase5ID("consumerId", "ConsumerID"), phase5ID("purposeId", "PurposeID"), phase5ID("targetId", "TargetID"),
			phase5ID("materialVersion", "MaterialVersion"), phase5Digest("fingerprint", "Fingerprint"),
			phase5Enum("status", "Status", "staged", "active", "unavailable", "revoked"),
			phase5Positive("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5Timestamp("resolvedAt", "ResolvedAt"), phase5ID("resolverId", "ResolverID"),
			phase5Enum("result", "Result", "resolved", "unavailable", "denied"),
			phase5ID("reasonCode", "ReasonCode"),
		),
	}
}

func phase5RecoveryJobSchemas() []SchemaDefinition {
	return []SchemaDefinition{
		phase5Schema(backupPolicySchemaID,
			phase5ID("policyId", "PolicyID"), phase5ID("sourceId", "SourceID"),
			phase5Digest("scopeDigest", "ScopeDigest"), phase5ID("retentionClass", "RetentionClass"),
			phase5ID("verificationRequirement", "VerificationRequirement"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Positive("revision", "Revision"),
		),
		phase5Schema(backupJobSchemaID,
			phase5ID("jobId", "JobID"), phase5ID("policyId", "PolicyID"),
			phase5Enum("sourceKind", "SourceKind", "fixture", "local", "independent"),
			phase5Enum("proofClass", "ProofClass", "fixture", "live"),
			phase5NullableID("pointId", "PointID"),
			phase5Enum("status", "Status", "queued", "running", "failed", "verified", "uncertain"),
			phase5NullableID("runId", "RunID"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5NullableDigest("verificationDigest", "VerificationDigest"),
		),
		phase5Schema(recoveryPointSchemaID,
			phase5ID("pointId", "PointID"),
			phase5Enum("sourceKind", "SourceKind", "fixture", "local", "independent"),
			phase5Enum("proofClass", "ProofClass", "fixture", "live"),
			phase5Digest("contentDigest", "ContentDigest"), phase5Digest("manifestDigest", "ManifestDigest"),
			phase5Timestamp("createdAt", "CreatedAt"), phase5NullableTimestamp("verifiedAt", "VerifiedAt"),
			phase5Enum("verificationStatus", "VerificationStatus", "pending", "verified", "failed"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5IDs("dependencies", "Dependencies", 256),
		),
		phase5Schema(auditCheckpointSchemaID,
			phase5ID("checkpointId", "CheckpointID"), phase5Positive("firstEventId", "FirstEventID"),
			phase5Positive("lastEventId", "LastEventID"), phase5Digest("chainDigest", "ChainDigest"),
			phase5NullableDigest("independentCopyDigest", "IndependentCopyDigest"),
			phase5Enum("sourceKind", "SourceKind", "fixture", "local", "independent"),
			phase5Enum("proofClass", "ProofClass", "fixture", "live"),
			phase5NullableTimestamp("verifiedAt", "VerifiedAt"),
			phase5Enum("verificationStatus", "VerificationStatus", "pending", "verified", "failed"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5Schema(restoreBindingSchemaID,
			phase5ID("pointId", "PointID"), phase5IDs("dependencyIds", "DependencyIDs", 256),
			FieldDefinition{JSONName: "targetIds", GoName: "TargetIDs", Kind: ValueArray, Required: true, ItemKind: ValueString, MinItems: intPointer(1), MaxItems: intPointer(64), UniqueItems: true},
			phase5Digest("targetDigest", "TargetDigest"), phase5ID("planId", "PlanID"), phase5Digest("planDigest", "PlanDigest"),
			phase5ID("humanAcknowledgementId", "HumanAcknowledgementID"),
			phase5Digest("formerControllerFenceDigest", "FormerControllerFenceDigest"),
			phase5ID("priorInstanceId", "PriorInstanceID"), phase5ID("newInstanceId", "NewInstanceID"),
			phase5Nonnegative("priorRecoveryEpoch", "PriorRecoveryEpoch"), phase5Positive("nextRecoveryEpoch", "NextRecoveryEpoch"),
			phase5Enum("status", "Status", "planned", "fenced", "restoring", "verification-required", "verified", "failed", "uncertain"),
		),
		phase5Schema(restoreVerificationSchemaID,
			phase5ID("planId", "PlanID"), phase5Digest("planDigest", "PlanDigest"), phase5ID("pointId", "PointID"),
			phase5Digest("targetDigest", "TargetDigest"), phase5Bool("fenceVerified", "FenceVerified"),
			phase5Bool("databaseVerified", "DatabaseVerified"), phase5Bool("auditVerified", "AuditVerified"),
			phase5NullableTimestamp("verifiedAt", "VerifiedAt"), phase5Positive("nextRecoveryEpoch", "NextRecoveryEpoch"),
			phase5Enum("status", "Status", "failed", "incomplete", "verified"),
		),
		phase5Schema(scheduledJobPolicySchemaID,
			phase5ID("policyId", "PolicyID"), phase5Positive("revision", "Revision"),
			phase5Enum("actionKind", "ActionKind", "backup", "audit-checkpoint", "gate-check"),
			FieldDefinition{JSONName: "exactTargetIds", GoName: "ExactTargetIDs", Kind: ValueArray, Required: true, ItemKind: ValueString, MinItems: intPointer(1), MaxItems: intPointer(64), UniqueItems: true},
			phase5Digest("actionDigest", "ActionDigest"), phase5Digest("targetDigest", "TargetDigest"),
			phase5Interval("intervalSeconds", "IntervalSeconds"),
			phase5Bool("enabled", "Enabled"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5Schema(scheduledJobSchemaID,
			phase5ID("jobId", "JobID"), phase5ID("policyId", "PolicyID"),
			phase5Positive("policyRevision", "PolicyRevision"), phase5Digest("actionDigest", "ActionDigest"),
			phase5Digest("targetDigest", "TargetDigest"), phase5NullableID("runId", "RunID"),
			phase5Enum("status", "Status", "queued", "running", "failed", "succeeded", "uncertain"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
	}
}

func phase5Request(identifier string, fields ...FieldDefinition) SchemaDefinition {
	base := []FieldDefinition{
		phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"),
		phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		phase5Digest("targetDigest", "TargetDigest"),
		phase5ID("idempotencyKey", "IdempotencyKey"),
	}
	return phase5Schema(identifier, append(base, fields...)...)
}

func phase5CredentialRequest(identifier string, fields ...FieldDefinition) SchemaDefinition {
	schema := phase5Request(identifier, fields...)
	schema.Version = "1.1.0"
	schema.Fields[1].Enum = []string{"1.1.0"}
	return schema
}

func phase5RequestSchemas() []SchemaDefinition {
	return []SchemaDefinition{
		phase5GateSchema(gateEvidenceFactSchemaID,
			phase5ID("factId", "FactID"), phase5Digest("valueDigest", "ValueDigest"),
		),
		phase5GateSchema(gateEvidenceCheckSchemaID,
			phase5ID("checkId", "CheckID"), phase5Version("verifierVersion", "VerifierVersion"),
			phase5Enum("result", "Result", "passed", "failed", "unknown"), phase5Digest("resultDigest", "ResultDigest"),
		),
		phase5GateSchema(gateEvidenceAttachmentSchemaID,
			phase5Digest("digest", "Digest"), phase5Positive("sizeBytes", "SizeBytes"),
			FieldDefinition{JSONName: "mediaType", GoName: "MediaType", Kind: ValueString, Required: true, MaxLength: intPointer(128)},
		),
		phase5GateSchema(gateEvidenceBundleSchemaID,
			FieldDefinition{JSONName: "facts", GoName: "Facts", Kind: ValueArray, Required: true, ItemRef: gateEvidenceFactSchemaID, MaxItems: intPointer(64)},
			FieldDefinition{JSONName: "checks", GoName: "Checks", Kind: ValueArray, Required: true, ItemRef: gateEvidenceCheckSchemaID, MaxItems: intPointer(64)},
			FieldDefinition{JSONName: "attachments", GoName: "Attachments", Kind: ValueArray, Required: true, ItemRef: gateEvidenceAttachmentSchemaID, MaxItems: intPointer(16)},
			phase5ID("collectorId", "CollectorID"), phase5Timestamp("observedAt", "ObservedAt"),
		),
		phase5GateSchema(gateEvidenceSubmissionSchemaID,
			phase5ID("draftId", "DraftID"), phase5ID("changeId", "ChangeID"), phase5ID("evidenceId", "EvidenceID"),
			phase5Enum("status", "Status", "draft"), phase5Nonnegative("stateRevision", "StateRevision"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5GateSchema(gateProfileDraftSubmissionSchemaID,
			phase5ID("draftId", "DraftID"), phase5ID("changeId", "ChangeID"), phase5ID("bindingId", "BindingID"),
			phase5Enum("status", "Status", "draft"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5Request(gateCheckRequestSchemaID,
			phase5GateID(), phase5ID("subjectId", "SubjectID"),
			phase5Version("definitionVersion", "DefinitionVersion"),
		),
		phase5GateRequest(gateEvidenceRequestSchemaID,
			phase5ID("evidenceId", "EvidenceID"), phase5GateID(), phase5ID("subjectId", "SubjectID"),
			phase5Version("definitionVersion", "DefinitionVersion"), phase5Version("evaluatorVersion", "EvaluatorVersion"),
			phase5NullableID("supersedesEvidenceId", "SupersedesEvidenceID"),
			phase5NullableID("revokesEvidenceId", "RevokesEvidenceID"),
			phase5Digest("artifactDigest", "ArtifactDigest"), phase5Timestamp("observedAt", "ObservedAt"),
			FieldDefinition{JSONName: "bundle", GoName: "Bundle", Kind: ValueObject, Required: true, Ref: gateEvidenceBundleSchemaID},
		),
		phase5GateRequest(gateProfileDraftRequestSchemaID,
			phase5ID("bindingId", "BindingID"), phase5ID("profileId", "ProfileID"), phase5Version("profileVersion", "ProfileVersion"),
			phase5ID("policyId", "PolicyID"), phase5Version("policyVersion", "PolicyVersion"),
			FieldDefinition{JSONName: "capabilities", GoName: "Capabilities", Kind: ValueArray, Required: true, ItemKind: ValueString, MaxItems: intPointer(64), UniqueItems: true},
		),
		phase5Request(backupRunRequestSchemaID,
			phase5ID("policyId", "PolicyID"), phase5Positive("policyRevision", "PolicyRevision"),
			phase5ID("planId", "PlanID"), phase5Digest("planDigest", "PlanDigest"),
			phase5ID("humanAcknowledgementId", "HumanAcknowledgementID"),
		),
		phase5Request(backupVerifyRequestSchemaID,
			phase5ID("jobId", "JobID"), phase5ID("pointId", "PointID"),
		),
		phase5Request(restoreRequestSchemaID,
			phase5ID("pointId", "PointID"), phase5IDs("dependencyIds", "DependencyIDs", 256),
			FieldDefinition{JSONName: "targetIds", GoName: "TargetIDs", Kind: ValueArray, Required: true, ItemKind: ValueString, MinItems: intPointer(1), MaxItems: intPointer(64), UniqueItems: true},
			phase5ID("priorInstanceId", "PriorInstanceID"), phase5ID("newInstanceId", "NewInstanceID"),
			phase5Nonnegative("priorRecoveryEpoch", "PriorRecoveryEpoch"),
		),
		phase5Request(restoreRunRequestSchemaID,
			phase5ID("pointId", "PointID"), phase5ID("planId", "PlanID"), phase5Digest("planDigest", "PlanDigest"),
			phase5ID("humanAcknowledgementId", "HumanAcknowledgementID"),
			phase5Digest("formerControllerFenceDigest", "FormerControllerFenceDigest"),
			phase5ID("priorInstanceId", "PriorInstanceID"), phase5ID("newInstanceId", "NewInstanceID"),
			phase5Nonnegative("priorRecoveryEpoch", "PriorRecoveryEpoch"), phase5Positive("nextRecoveryEpoch", "NextRecoveryEpoch"),
		),
		phase5Request(restoreVerifyRequestSchemaID,
			phase5ID("pointId", "PointID"), phase5ID("planId", "PlanID"), phase5Digest("planDigest", "PlanDigest"),
			phase5Positive("nextRecoveryEpoch", "NextRecoveryEpoch"),
		),
		phase5Request(scheduledJobRequestSchemaID,
			phase5ID("policyId", "PolicyID"), phase5Positive("policyRevision", "PolicyRevision"),
			phase5Digest("actionDigest", "ActionDigest"), phase5ID("planId", "PlanID"),
			phase5Digest("planDigest", "PlanDigest"), phase5ID("humanAcknowledgementId", "HumanAcknowledgementID"),
		),
		phase5CredentialRequest(credentialReferenceRequestSchemaID,
			phase5ID("referenceId", "ReferenceID"), phase5ID("consumerId", "ConsumerID"),
			phase5ID("purposeId", "PurposeID"), phase5ID("targetId", "TargetID"), phase5ID("resolverId", "ResolverID"),
			phase5ID("materialVersion", "MaterialVersion"), phase5Digest("fingerprint", "Fingerprint"),
		),
		phase5CredentialRequest(credentialImportRequestSchemaID,
			phase5ID("referenceId", "ReferenceID"), phase5ID("consumerId", "ConsumerID"),
			phase5ID("purposeId", "PurposeID"), phase5ID("targetId", "TargetID"), phase5Enum("resolverId", "ResolverID", "native-systemd"),
			phase5ID("materialVersion", "MaterialVersion"),
		),
		phase5CredentialSchema(credentialImportSubmissionSchemaID,
			phase5ID("draftId", "DraftID"), phase5ID("referenceId", "ReferenceID"),
			phase5Digest("ciphertextFingerprint", "CiphertextFingerprint"),
			phase5Enum("status", "Status", "draft"), phase5Nonnegative("stateRevision", "StateRevision"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5Request(auditCheckpointRequestSchemaID,
			phase5Positive("firstEventId", "FirstEventID"), phase5Positive("lastEventId", "LastEventID"),
		),
		phase5Request(databaseExportRequestSchemaID,
			phase5ID("exportId", "ExportID"), phase5Enum("kind", "Kind", "sanitized-control", "sanitized-audit"),
		),
		phase5GateSchema(gateListDataSchemaID,
			FieldDefinition{JSONName: "gates", GoName: "Gates", Kind: ValueArray, Required: true, ItemRef: gateViewSchemaID, MaxItems: intPointer(256)},
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5Schema(backupStatusDataSchemaID,
			FieldDefinition{JSONName: "policies", GoName: "Policies", Kind: ValueArray, Required: true, ItemRef: backupPolicySchemaID, MaxItems: intPointer(256)},
			FieldDefinition{JSONName: "jobs", GoName: "Jobs", Kind: ValueArray, Required: true, ItemRef: backupJobSchemaID, MaxItems: intPointer(256)},
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5Schema(auditCheckpointListDataSchemaID,
			FieldDefinition{JSONName: "checkpoints", GoName: "Checkpoints", Kind: ValueArray, Required: true, ItemRef: auditCheckpointSchemaID, MaxItems: intPointer(256)},
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5Schema(browserRestoreStatusSchemaID,
			phase5ID("pointId", "PointID"), phase5ID("planId", "PlanID"), phase5Digest("planDigest", "PlanDigest"),
			phase5Digest("targetDigest", "TargetDigest"),
			phase5Enum("status", "Status", "planned", "fenced", "restoring", "verification-required", "verified", "failed", "uncertain"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5Enum("verificationStatus", "VerificationStatus", "pending", "incomplete", "verified", "failed"),
		),
		phase5Schema(sanitizedExportDataSchemaID,
			phase5ID("exportId", "ExportID"), phase5Enum("kind", "Kind", "sanitized-control", "sanitized-audit"),
			phase5Digest("contentDigest", "ContentDigest"), phase5Timestamp("createdAt", "CreatedAt"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
	}
}

func phase5Endpoint(identifier, method, path, request, data string, browser bool) EndpointDefinition {
	audiences := []EndpointAudience{AudienceOperator}
	if browser {
		audiences = append(audiences, AudienceBrowser)
	}
	return EndpointDefinition{
		ID: identifier, Method: method, Path: path, RequestSchema: request, DataSchema: data,
		Availability: AvailabilityPlanned, OwnerPhase: "5", Stream: StreamFinite, Audiences: audiences,
	}
}

func phase5AvailableGateEndpoint(identifier, method, path, request, data string, browser bool) EndpointDefinition {
	endpoint := phase5Endpoint(identifier, method, path, request, data, browser)
	endpoint.Availability = AvailabilityAvailable
	return endpoint
}

func phase5GateRequest(identifier string, fields ...FieldDefinition) SchemaDefinition {
	schema := phase5Request(identifier, fields...)
	schema.Version = "1.1.0"
	schema.Fields[1].Enum = []string{"1.1.0"}
	return schema
}

func phase5Endpoints() []EndpointDefinition {
	return []EndpointDefinition{
		{ID: "api.v1.gate-profile-drafts.create", Method: "POST", Path: "/api/v1/gates/profile-drafts", RequestSchema: gateProfileDraftRequestSchemaID, DataSchema: gateProfileDraftSubmissionSchemaID, Availability: AvailabilityAvailable, OwnerPhase: "5", Stream: StreamFinite, Audiences: []EndpointAudience{AudienceOperator}},
		phase5AvailableGateEndpoint("api.v1.gates.list", "GET", "/api/v1/gates", "", gateListDataSchemaID, true),
		phase5AvailableGateEndpoint("api.v1.gates.get", "GET", "/api/v1/gates/{gateId}", "", gateViewSchemaID, true),
		phase5AvailableGateEndpoint("api.v1.gates.check", "POST", "/api/v1/gates/check", gateCheckRequestSchemaID, gateEvaluationSchemaID, true),
		phase5AvailableGateEndpoint("api.v1.gate-evidence.create", "POST", "/api/v1/gates/{gateId}/evidence", gateEvidenceRequestSchemaID, gateEvidenceSubmissionSchemaID, false),
		phase5Endpoint("api.v1.credential-references.get", "GET", "/api/v1/credential-references/{referenceId}", "", credentialReferenceSchemaID, false),
		phase5Endpoint("api.v1.credential-resolution-records.get", "GET", "/api/v1/credential-resolution-records/{recordId}", "", credentialResolutionRecordSchemaID, false),
		{ID: "api.v1.credential-references.import-stream", Method: "POST", Path: "/api/v1/credential-references/{referenceId}/import-stream", RequestSchema: credentialImportRequestSchemaID, DataSchema: credentialImportSubmissionSchemaID, Availability: AvailabilityAvailable, OwnerPhase: "5", Stream: StreamFinite, Audiences: []EndpointAudience{AudienceOperator}, RequestEncoding: "binary", TransportScope: "local", MaxRequestBytes: 4096},
		phase5Endpoint("api.v1.backups.status", "GET", "/api/v1/backups/status", "", backupStatusDataSchemaID, true),
		phase5Endpoint("api.v1.backups.run", "POST", "/api/v1/backups/run", backupRunRequestSchemaID, backupJobSchemaID, false),
		phase5Endpoint("api.v1.backups.verify", "POST", "/api/v1/backups/{jobId}/verify", backupVerifyRequestSchemaID, backupJobSchemaID, false),
		phase5Endpoint("api.v1.recovery-points.get", "GET", "/api/v1/recovery-points/{pointId}", "", recoveryPointSchemaID, true),
		phase5Endpoint("api.v1.audit-checkpoints.list", "GET", "/api/v1/audit-checkpoints", "", auditCheckpointListDataSchemaID, true),
		phase5Endpoint("api.v1.audit-checkpoints.create", "POST", "/api/v1/audit-checkpoints", auditCheckpointRequestSchemaID, auditCheckpointSchemaID, false),
		phase5Endpoint("api.v1.restores.plan", "POST", "/api/v1/restores/plans", restoreRequestSchemaID, restoreBindingSchemaID, false),
		phase5Endpoint("api.v1.restores.get", "GET", "/api/v1/restores/plans/{planId}", "", browserRestoreStatusSchemaID, true),
		phase5Endpoint("api.v1.restores.run", "POST", "/api/v1/restores/plans/{planId}/run", restoreRunRequestSchemaID, restoreBindingSchemaID, false),
		phase5Endpoint("api.v1.restores.verify", "POST", "/api/v1/restores/plans/{planId}/verify", restoreVerifyRequestSchemaID, restoreVerificationSchemaID, false),
		phase5Endpoint("api.v1.scheduled-job-policies.get", "GET", "/api/v1/scheduled-job-policies/{policyId}", "", scheduledJobPolicySchemaID, true),
		phase5Endpoint("api.v1.scheduled-jobs.create", "POST", "/api/v1/scheduled-jobs", scheduledJobRequestSchemaID, scheduledJobSchemaID, false),
	}
}

func phase5CommandSchemas(path string) (request string, data string) {
	switch path {
	case "audit":
		return "", auditCheckpointListDataSchemaID
	case "gate list":
		return "", gateListDataSchemaID
	case "gate inspect":
		return "", gateViewSchemaID
	case "gate check":
		return gateCheckRequestSchemaID, gateEvaluationSchemaID
	case "gate evidence":
		return gateEvidenceRequestSchemaID, gateEvidenceSubmissionSchemaID
	case "gate profile draft":
		return gateProfileDraftRequestSchemaID, gateProfileDraftSubmissionSchemaID
	case "backup status":
		return "", backupStatusDataSchemaID
	case "backup run", "database backup":
		return backupRunRequestSchemaID, backupJobSchemaID
	case "backup verify", "database verify":
		return backupVerifyRequestSchemaID, backupJobSchemaID
	case "restore plan", "database restore":
		return restoreRequestSchemaID, restoreBindingSchemaID
	case "restore run":
		return restoreRunRequestSchemaID, restoreBindingSchemaID
	case "restore verify":
		return restoreVerifyRequestSchemaID, restoreVerificationSchemaID
	case "database export":
		return databaseExportRequestSchemaID, sanitizedExportDataSchemaID
	default:
		return "", ""
	}
}

func phase5GateEvidenceTransitions() []TransitionDefinition {
	return []TransitionDefinition{{From: "draft", To: "applied"}, {From: "draft", To: "revoked"}, {From: "applied", To: "revoked"}}
}

func phase5BackupJobTransitions() []TransitionDefinition {
	return []TransitionDefinition{{From: "queued", To: "running"}, {From: "queued", To: "failed"}, {From: "running", To: "verified"}, {From: "running", To: "failed"}, {From: "running", To: "uncertain"}}
}

func phase5RestoreTransitions() []TransitionDefinition {
	return []TransitionDefinition{{From: "planned", To: "fenced"}, {From: "planned", To: "failed"}, {From: "fenced", To: "restoring"}, {From: "fenced", To: "failed"}, {From: "restoring", To: "verification-required"}, {From: "restoring", To: "failed"}, {From: "restoring", To: "uncertain"}, {From: "verification-required", To: "verified"}, {From: "verification-required", To: "failed"}, {From: "verification-required", To: "uncertain"}}
}

func phase5ScheduledJobTransitions() []TransitionDefinition {
	return []TransitionDefinition{{From: "queued", To: "running"}, {From: "queued", To: "failed"}, {From: "running", To: "succeeded"}, {From: "running", To: "failed"}, {From: "running", To: "uncertain"}}
}
