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

func phase5ID(name, goName string) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueString, Required: true, Pattern: `^[a-z][a-z0-9._:-]{0,127}$`}
}

func phase5Digest(name, goName string) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueString, Required: true, Pattern: `^sha256:[a-f0-9]{64}$`}
}

func phase5Version(name, goName string) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueString, Required: true, Pattern: `^1\.[0-9]+\.[0-9]+$`}
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
		phase5Schema(gateDefinitionSchemaID,
			phase5ID("gateId", "GateID"), phase5Version("definitionVersion", "DefinitionVersion"),
			phase5Enum("layer", "Layer", "platform", "adapter", "deployment-profile", "site"),
			phase5IDs("subjectKinds", "SubjectKinds", 64),
			phase5Enum("applicability", "Applicability", "always", "capability", "profile", "subject"),
			phase5IDs("prerequisiteGateIds", "PrerequisiteGateIDs", 64),
			FieldDefinition{JSONName: "evidenceSchemaId", GoName: "EvidenceSchemaID", Kind: ValueString, Required: true, Pattern: `^[a-z0-9][a-z0-9./-]*$`},
			phase5Version("evaluatorVersion", "EvaluatorVersion"),
			phase5Positive("freshnessSeconds", "FreshnessSeconds"),
			phase5Bool("recoveryEpochBound", "RecoveryEpochBound"),
		),
		phase5Schema(gateEvidenceSchemaID,
			phase5ID("evidenceId", "EvidenceID"), phase5ID("gateId", "GateID"), phase5ID("subjectId", "SubjectID"),
			phase5Version("definitionVersion", "DefinitionVersion"), phase5Version("evaluatorVersion", "EvaluatorVersion"),
			phase5Enum("sourceKind", "SourceKind", "fixture", "local", "independent"),
			phase5Enum("proofClass", "ProofClass", "fixture", "live"),
			phase5Digest("artifactDigest", "ArtifactDigest"),
			phase5Timestamp("observedAt", "ObservedAt"), phase5Timestamp("expiresAt", "ExpiresAt"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5Enum("status", "Status", "draft", "applied", "revoked"),
		),
		phase5Schema(gateEvaluationSchemaID,
			phase5ID("evaluationId", "EvaluationID"), phase5ID("gateId", "GateID"), phase5ID("subjectId", "SubjectID"),
			phase5Version("definitionVersion", "DefinitionVersion"), phase5Version("evaluatorVersion", "EvaluatorVersion"),
			phase5IDs("evidenceIds", "EvidenceIDs", 64), phase5Timestamp("evaluatedAt", "EvaluatedAt"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5Enum("outcome", "Outcome", "passed", "blocked", "not-applicable", "stale", "unknown"),
			phase5ID("reasonCode", "ReasonCode"),
		),
		phase5Schema(credentialReferenceSchemaID,
			phase5ID("referenceId", "ReferenceID"), phase5ID("consumerId", "ConsumerID"), phase5ID("purposeId", "PurposeID"),
			phase5ID("materialVersion", "MaterialVersion"), phase5Digest("fingerprint", "Fingerprint"),
			phase5Enum("status", "Status", "active", "unavailable", "revoked"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5Schema(credentialResolutionRecordSchemaID,
			phase5ID("recordId", "RecordID"), phase5ID("referenceId", "ReferenceID"),
			phase5ID("consumerId", "ConsumerID"), phase5ID("purposeId", "PurposeID"),
			phase5ID("materialVersion", "MaterialVersion"), phase5Digest("fingerprint", "Fingerprint"),
			phase5Enum("status", "Status", "active", "unavailable", "revoked"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Timestamp("resolvedAt", "ResolvedAt"),
			phase5ID("resolverId", "ResolverID"), phase5Enum("result", "Result", "resolved", "unavailable", "denied"),
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
			phase5Digest("actionDigest", "ActionDigest"), phase5Interval("intervalSeconds", "IntervalSeconds"),
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
