package metadata

const (
	gateDefinitionSchemaID                    = "vegastack-labs.dev/gate-definition"
	gateEvidenceSchemaID                      = "vegastack-labs.dev/gate-evidence"
	gateEvaluationSchemaID                    = "vegastack-labs.dev/gate-evaluation"
	credentialReferenceSchemaID               = "vegastack-labs.dev/credential-reference"
	credentialResolutionRecordSchemaID        = "vegastack-labs.dev/credential-resolution-record"
	backupPolicySchemaID                      = "vegastack-labs.dev/backup-policy"
	backupDependencySchemaID                  = "vegastack-labs.dev/backup-dependency"
	backupPolicyDraftRequestSchemaID          = "vegastack-labs.dev/backup-policy-draft-request"
	backupPolicyDraftSubmissionSchemaID       = "vegastack-labs.dev/backup-policy-draft-submission"
	backupJobSchemaID                         = "vegastack-labs.dev/backup-job"
	backupVerificationAttemptSchemaID         = "vegastack-labs.dev/backup-verification-attempt"
	backupLastGoodSchemaID                    = "vegastack-labs.dev/backup-last-good"
	backupLocalRetirementStatusSchemaID       = "vegastack-labs.dev/backup-local-retirement-status"
	backupOffsiteStatusSchemaID               = "vegastack-labs.dev/backup-offsite-status"
	offsiteRunSpecSchemaID                    = "vegastack-labs.dev/offsite-run-spec"
	backupRetentionLockSchemaID               = "vegastack-labs.dev/backup-retention-lock"
	backupRetentionLockCatalogSchemaID        = "vegastack-labs.dev/local-retention-lock-catalog"
	backupRetentionLockDraftRequestID         = "vegastack-labs.dev/backup-retention-lock-draft-request"
	backupRetentionLockDraftSubmissionID      = "vegastack-labs.dev/backup-retention-lock-draft-submission"
	backupRetirementDraftRequestID            = "vegastack-labs.dev/backup-retirement-draft-request"
	backupRetirementDraftSubmissionID         = "vegastack-labs.dev/backup-retirement-draft-submission"
	backupOffsiteRetirementDryRunRequestID    = "vegastack-labs.dev/backup-offsite-retirement-dry-run-request"
	backupOffsiteRetirementDryRunDataID       = "vegastack-labs.dev/backup-offsite-retirement-dry-run-data"
	backupOffsiteRetirementRuleID             = "vegastack-labs.dev/backup-offsite-retirement-rule"
	backupOffsiteRetirementObjectID           = "vegastack-labs.dev/backup-offsite-retirement-object"
	backupOffsiteRetirementSurvivorBindingID  = "vegastack-labs.dev/backup-offsite-retirement-survivor-binding"
	backupOffsiteRetirementStageRequestID     = "vegastack-labs.dev/backup-offsite-retirement-stage-request"
	backupOffsiteRetirementStageSubmissionID  = "vegastack-labs.dev/backup-offsite-retirement-stage-submission"
	backupTrustSourceDraftRequestSchemaID     = "vegastack-labs.dev/backup-trust-source-draft-request"
	recoveryPointSchemaID                     = "vegastack-labs.dev/recovery-point"
	auditCheckpointSchemaID                   = "vegastack-labs.dev/audit-checkpoint"
	restoreBindingSchemaID                    = "vegastack-labs.dev/restore-binding"
	restoreSourceBindingSchemaID              = "vegastack-labs.dev/restore-source-binding"
	restoreDependencyBindingSchemaID          = "vegastack-labs.dev/restore-dependency-binding"
	restoreFenceItemSchemaID                  = "vegastack-labs.dev/restore-fence-item"
	restoreAuditDecisionSchemaID              = "vegastack-labs.dev/restore-audit-decision"
	restoreCanaryResultSchemaID               = "vegastack-labs.dev/restore-canary-result"
	restoreVerificationSchemaID               = "vegastack-labs.dev/restore-verification"
	scheduledJobPolicySchemaID                = "vegastack-labs.dev/scheduled-job-policy"
	scheduledPolicyDraftSubmissionSchemaID    = "vegastack-labs.dev/scheduled-policy-draft-submission"
	scheduledJobSchemaID                      = "vegastack-labs.dev/scheduled-job"
	gateCheckRequestSchemaID                  = "vegastack-labs.dev/gate-check-request"
	gateEvidenceRequestSchemaID               = "vegastack-labs.dev/gate-evidence-request"
	gateProfileDraftRequestSchemaID           = "vegastack-labs.dev/gate-profile-draft-request"
	gateProfileDraftSubmissionSchemaID        = "vegastack-labs.dev/gate-profile-draft-submission"
	gateEvidenceFactSchemaID                  = "vegastack-labs.dev/gate-evidence-fact"
	gateEvidenceCheckSchemaID                 = "vegastack-labs.dev/gate-evidence-check"
	gateEvidenceAttachmentSchemaID            = "vegastack-labs.dev/gate-evidence-attachment"
	gateEvidenceBundleSchemaID                = "vegastack-labs.dev/gate-evidence-bundle"
	gateEvidenceSubmissionSchemaID            = "vegastack-labs.dev/gate-evidence-submission"
	gateViewSchemaID                          = "vegastack-labs.dev/gate-view"
	backupRunRequestSchemaID                  = "vegastack-labs.dev/backup-run-request"
	backupVerifyRequestSchemaID               = "vegastack-labs.dev/backup-verify-request"
	restoreRequestSchemaID                    = "vegastack-labs.dev/restore-request"
	browserRestoreDraftRequestSchemaID        = "vegastack-labs.dev/browser-restore-draft-request"
	restoreRunRequestSchemaID                 = "vegastack-labs.dev/restore-run-request"
	restoreVerifyRequestSchemaID              = "vegastack-labs.dev/restore-verify-request"
	scheduledJobRequestSchemaID               = "vegastack-labs.dev/scheduled-job-request"
	scheduledJobCancelRequestSchemaID         = "vegastack-labs.dev/scheduled-job-cancel-request"
	credentialReferenceRequestSchemaID        = "vegastack-labs.dev/credential-reference-request"
	credentialImportRequestSchemaID           = "vegastack-labs.dev/credential-import-request"
	credentialImportSubmissionSchemaID        = "vegastack-labs.dev/credential-import-submission"
	credentialLifecycleRequestSchemaID        = "vegastack-labs.dev/credential-lifecycle-request"
	credentialNativeConsumerSchemaID          = "vegastack-labs.dev/credential-native-consumer"
	credentialNativeDeniedReaderID            = "vegastack-labs.dev/credential-native-denied-reader"
	credentialLifecycleSubmissionID           = "vegastack-labs.dev/credential-lifecycle-submission"
	auditCheckpointRequestSchemaID            = "vegastack-labs.dev/audit-checkpoint-request"
	databaseExportRequestSchemaID             = "vegastack-labs.dev/database-export-request"
	gateListDataSchemaID                      = "vegastack-labs.dev/gate-list-data"
	backupStatusDataSchemaID                  = "vegastack-labs.dev/backup-status-data"
	auditCheckpointListDataSchemaID           = "vegastack-labs.dev/audit-checkpoint-list-data"
	auditVerificationDataSchemaID             = "vegastack-labs.dev/audit-verification-data"
	recoveryWitnessCollectionDataSchemaID     = "vegastack-labs.dev/recovery-witness-collection-data"
	browserRestoreStatusSchemaID              = "vegastack-labs.dev/browser-restore-status"
	browserBackupStatusDataSchemaID           = "vegastack-labs.dev/browser-backup-status-data"
	browserRecoveryPointSchemaID              = "vegastack-labs.dev/browser-recovery-point"
	browserRecoveryPointListDataSchemaID      = "vegastack-labs.dev/browser-recovery-point-list-data"
	browserAuditCheckpointSchemaID            = "vegastack-labs.dev/browser-audit-checkpoint"
	browserAuditCheckpointListDataSchemaID    = "vegastack-labs.dev/browser-audit-checkpoint-list-data"
	browserAuditVerificationDataSchemaID      = "vegastack-labs.dev/browser-audit-verification-data"
	browserRestoreDraftSubmissionSchemaID     = "vegastack-labs.dev/browser-restore-draft-submission"
	browserRestoreStatusListDataSchemaID      = "vegastack-labs.dev/browser-restore-status-list-data"
	browserScheduledJobPolicySchemaID         = "vegastack-labs.dev/browser-scheduled-job-policy"
	browserScheduledJobPolicyListDataSchemaID = "vegastack-labs.dev/browser-scheduled-job-policy-list-data"
	browserScheduledJobSchemaID               = "vegastack-labs.dev/browser-scheduled-job"
	browserScheduledJobListDataSchemaID       = "vegastack-labs.dev/browser-scheduled-job-list-data"
	sanitizedExportDataSchemaID               = "vegastack-labs.dev/sanitized-export-data"
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

func phase5AuditSchema(identifier string, fields ...FieldDefinition) SchemaDefinition {
	schema := phase5Schema(identifier, fields...)
	schema.Version = "1.1.0"
	schema.Fields[1].Enum = []string{"1.1.0"}
	return schema
}

func phase5RestoreSchema(identifier string, fields ...FieldDefinition) SchemaDefinition {
	schema := phase5Schema(identifier, fields...)
	schema.Version = "1.1.0"
	schema.Fields[1].Enum = []string{"1.1.0"}
	return schema
}

func phase5RestoreRequest(identifier string, fields ...FieldDefinition) SchemaDefinition {
	schema := phase5Request(identifier, fields...)
	schema.Version = "1.1.0"
	schema.Fields[1].Enum = []string{"1.1.0"}
	return schema
}

// Backup creation contracts are versioned to 1.1.0 by issue #106. The draft,
// policy, job and recovery-point shapes are inert public metadata; they resolve
// no credential and publish no evidence.
func phase5BackupSchema(identifier string, fields ...FieldDefinition) SchemaDefinition {
	schema := phase5Schema(identifier, fields...)
	schema.Version = "1.1.0"
	schema.Fields[1].Enum = []string{"1.1.0"}
	return schema
}

func phase5BackupPolicySchema(fields ...FieldDefinition) SchemaDefinition {
	schema := phase5BackupSchema(backupPolicySchemaID, fields...)
	schema.Version = "1.2.0"
	schema.Fields[1].Enum = []string{"1.2.0"}
	return schema
}

func phase5BackupStatusSchema(fields ...FieldDefinition) SchemaDefinition {
	schema := phase5BackupSchema(backupStatusDataSchemaID, fields...)
	schema.Version = "1.3.0"
	schema.Fields[1].Enum = []string{"1.3.0"}
	return schema
}

func phase5BackupOffsiteStatusSchema(fields ...FieldDefinition) SchemaDefinition {
	schema := phase5BackupSchema(backupOffsiteStatusSchemaID, fields...)
	schema.Version = "1.2.0"
	schema.Fields[1].Enum = []string{"1.2.0"}
	return schema
}

func phase5BackupRequest(identifier string, fields ...FieldDefinition) SchemaDefinition {
	schema := phase5Request(identifier, fields...)
	schema.Version = "1.1.0"
	schema.Fields[1].Enum = []string{"1.1.0"}
	return schema
}

func phase5BackupVerifyRequest(fields ...FieldDefinition) SchemaDefinition {
	schema := phase5Request(backupVerifyRequestSchemaID, fields...)
	schema.Version = "1.1.0"
	schema.Fields[1].Enum = []string{"1.1.0"}
	return schema
}

func phase5BackupVerificationSchema(fields ...FieldDefinition) SchemaDefinition {
	schema := phase5BackupSchema(backupVerificationAttemptSchemaID, fields...)
	schema.Version = "1.2.0"
	schema.Fields[1].Enum = []string{"1.2.0"}
	return schema
}

func phase5ScheduleSchema(identifier string, fields ...FieldDefinition) SchemaDefinition {
	schema := phase5Schema(identifier, fields...)
	schema.Version = "1.1.0"
	schema.Fields[1].Enum = []string{"1.1.0"}
	return schema
}

func phase5ScheduleRequest(fields ...FieldDefinition) SchemaDefinition {
	schema := phase5Request(scheduledJobRequestSchemaID, fields...)
	schema.Version = "1.1.0"
	schema.Fields[1].Enum = []string{"1.1.0"}
	return schema
}

func phase5PageSchema(identifier, itemSchema string) SchemaDefinition {
	next := FieldDefinition{JSONName: "nextCursor", GoName: "NextCursor", Kind: ValueString, Required: true, Nullable: true, MaxLength: intPointer(2048)}
	return phase5Schema(identifier,
		FieldDefinition{JSONName: "items", GoName: "Items", Kind: ValueArray, Required: true, ItemRef: itemSchema, MaxItems: intPointer(100)},
		next, phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
	)
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

func phase5NullablePositive(name, goName string) FieldDefinition {
	field := phase5Positive(name, goName)
	field.Nullable = true
	return field
}

func phase5GateCredentialSchemas() []SchemaDefinition {
	return []SchemaDefinition{
		{ID: offsiteRunSpecSchemaID, Version: "1.0.0", Fields: []FieldDefinition{
			phase5ID("generationId", "GenerationID"), phase5ID("sourcePointId", "SourcePointID"),
			phase5Nonnegative("sourceRevision", "SourceRevision"),
			{JSONName: "snapshotPath", GoName: "SnapshotPath", Kind: ValueString, Required: true, Pattern: `^/[^\x00]*$`, MinLength: intPointer(2), MaxLength: intPointer(4096)},
			{JSONName: "repositoryUrl", GoName: "RepositoryURL", Kind: ValueString, Required: true, MinLength: intPointer(12), MaxLength: intPointer(4096)},
			phase5ID("parentReferenceId", "ParentReferenceID"), phase5ID("repositoryKeyReferenceId", "RepositoryKeyReferenceID"), phase5ID("observerReferenceId", "ObserverReferenceID"),
			phase5Digest("ruleDigest", "RuleDigest"), phase5Digest("g008EvidenceDigest", "G008EvidenceDigest"),
			phase5Positive("maximumBytes", "MaximumBytes"), phase5Positive("maximumPuts", "MaximumPUTs"), phase5Positive("maximumLists", "MaximumLISTs"),
			phase5Positive("maximumRetainedGenerations", "MaximumRetainedGenerations"), phase5Positive("ruleLimit", "RuleLimit"),
			phase5Positive("retentionSeconds", "RetentionSeconds"),
			{JSONName: "sessionTtlSeconds", GoName: "SessionTTLSeconds", Kind: ValueInteger, Required: true, Minimum: int64Pointer(1), Maximum: int64Pointer(900)},
		}},
		phase5Schema(recoveryWitnessCollectionDataSchemaID,
			phase5Digest("manifestDigest", "ManifestDigest"), phase5Timestamp("expiresAt", "ExpiresAt"),
			FieldDefinition{JSONName: "signedArtifactBase64", GoName: "SignedArtifactBase64", Kind: ValueString, Required: true, Pattern: `^[A-Za-z0-9_-]+$`, MaxLength: intPointer(350000)},
			FieldDefinition{JSONName: "protectedEnvelopeBase64", GoName: "ProtectedEnvelopeBase64", Kind: ValueString, Required: true, Pattern: `^[A-Za-z0-9_-]+$`, MaxLength: intPointer(10000)},
		),
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
		phase5Schema(backupTrustSourceDraftRequestSchemaID,
			phase5ID("sourceId", "SourceID"), phase5ID("dependencyId", "DependencyID"),
			phase5Enum("dependencyKind", "DependencyKind", "config", "image", "signature"),
			phase5ID("artifactId", "ArtifactID"), phase5Digest("artifactDigest", "ArtifactDigest"),
			phase5Digest("bundleDigest", "BundleDigest"), phase5ID("trustedRootReferenceId", "TrustedRootReferenceID"),
			phase5Digest("trustRootDigest", "TrustRootDigest"),
			FieldDefinition{JSONName: "signerIdentity", GoName: "SignerIdentity", Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(512)},
			FieldDefinition{JSONName: "signerIssuer", GoName: "SignerIssuer", Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(512)},
			phase5Positive("revision", "Revision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5ID("idempotencyKey", "IdempotencyKey"),
		),
		// BackupDependency is a nested sub-object (like a principal binding); it
		// carries no schema/schemaVersion envelope of its own.
		{ID: backupDependencySchemaID, Version: "1.1.0", ArtifactPath: schemaPath(backupDependencySchemaID), Fields: []FieldDefinition{
			phase5ID("dependencyId", "DependencyID"),
			phase5Enum("kind", "Kind", "binary", "schema", "config", "image", "signature"),
			phase5Digest("digest", "Digest"),
		}},
		phase5BackupPolicySchema(
			phase5ID("policyId", "PolicyID"), phase5ID("ownerId", "OwnerID"), phase5ID("sourceId", "SourceID"),
			phase5IDs("sourceSelectors", "SourceSelectors", 64),
			phase5ID("consistencyHookId", "ConsistencyHookID"),
			phase5NullableID("repositoryId", "RepositoryID"),
			phase5Enum("repositoryClass", "RepositoryClass", "none", "standard", "critical"),
			phase5Enum("scheduleIntent", "ScheduleIntent", "manual", "hourly", "daily", "weekly"),
			phase5Nonnegative("expectedBytes", "ExpectedBytes"), phase5Nonnegative("expectedGrowthBytes", "ExpectedGrowthBytes"),
			phase5Nonnegative("minimumFreeBytes", "MinimumFreeBytes"),
			phase5NullableID("encryptionKeyReferenceId", "EncryptionKeyReferenceID"),
			phase5NullableID("recoveryKeyReferenceId", "RecoveryKeyReferenceID"),
			phase5Nonnegative("retentionDays", "RetentionDays"), phase5ID("restoreTargetId", "RestoreTargetID"),
			FieldDefinition{JSONName: "dependencies", GoName: "Dependencies", Kind: ValueArray, Required: true, ItemRef: backupDependencySchemaID, MaxItems: intPointer(64)},
			phase5Bool("functionalTestRequired", "FunctionalTestRequired"),
			FieldDefinition{JSONName: "fullPayloadIntervalHours", GoName: "FullPayloadIntervalHours", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0), Maximum: int64Pointer(8760)},
			FieldDefinition{JSONName: "functionalTestIntervalHours", GoName: "FunctionalTestIntervalHours", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0), Maximum: int64Pointer(8760)},
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Positive("revision", "Revision"),
		),
		phase5BackupSchema(backupJobSchemaID,
			phase5ID("jobId", "JobID"), phase5ID("policyId", "PolicyID"),
			phase5Enum("sourceKind", "SourceKind", "fixture", "local", "independent"),
			phase5Enum("proofClass", "ProofClass", "fixture", "live"),
			phase5NullableID("pointId", "PointID"),
			phase5Enum("status", "Status", "queued", "running", "pending", "failed", "verified", "uncertain"),
			phase5NullableID("runId", "RunID"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5NullableDigest("verificationDigest", "VerificationDigest"),
		),
		phase5BackupVerificationSchema(
			phase5ID("verificationId", "VerificationID"), phase5ID("jobId", "JobID"), phase5ID("pointId", "PointID"),
			phase5NullableID("runId", "RunID"), phase5Enum("status", "Status", "pending", "fixture-only", "local-verified", "full-payload-due", "functional-test-due", "uncertain", "failed"),
			phase5Enum("proofClass", "ProofClass", "fixture", "live"), phase5NullableDigest("verificationDigest", "VerificationDigest"),
			phase5NullableTimestamp("verifiedAt", "VerifiedAt"), phase5NullableTimestamp("fullPayloadDueAt", "FullPayloadDueAt"),
			phase5NullableTimestamp("functionalTestDueAt", "FunctionalTestDueAt"), phase5NullableID("reasonCode", "ReasonCode"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5BackupSchema(backupLastGoodSchemaID,
			phase5Enum("repositoryClass", "RepositoryClass", "standard", "critical"), phase5ID("pointId", "PointID"),
			phase5ID("verificationId", "VerificationID"), phase5Digest("manifestDigest", "ManifestDigest"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5BackupSchema(backupLocalRetirementStatusSchemaID,
			phase5ID("intentId", "IntentID"), phase5ID("repositoryId", "RepositoryID"),
			phase5Enum("repositoryClass", "RepositoryClass", "standard", "critical"),
			phase5Enum("status", "Status", "planned", "in-progress", "uncertain", "verified", "failed"),
			phase5Digest("selectionDigest", "SelectionDigest"), phase5Digest("lockCatalogDigest", "LockCatalogDigest"),
			phase5Positive("lockCatalogSequence", "LockCatalogSequence"), phase5Digest("sourceCoverageDigest", "SourceCoverageDigest"),
			phase5Digest("expectedInventoryDigest", "ExpectedInventoryDigest"),
			phase5IDs("targetPointIds", "TargetPointIDs", 256), phase5IDs("survivorPointIds", "SurvivorPointIDs", 256),
			phase5Nonnegative("expectedReclaimBytes", "ExpectedReclaimBytes"),
			phase5NullableDigest("journalDigest", "JournalDigest"), phase5NullableDigest("survivorVerificationDigest", "SurvivorVerificationDigest"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5BackupOffsiteStatusSchema(
			phase5ID("generationId", "GenerationID"), phase5ID("sourcePointId", "SourcePointID"),
			phase5ID("repositoryId", "RepositoryID"),
			FieldDefinition{JSONName: "snapshotId", GoName: "SnapshotID", Kind: ValueString, Required: true, Pattern: `^[a-f0-9]{64}$`},
			phase5Enum("status", "Status", "pending", "fixture-only", "offsite-verified", "full-payload-due", "site-loss-blocked", "uncertain", "failed"),
			FieldDefinition{JSONName: "proofClass", GoName: "ProofClass", Kind: ValueString, Required: true, Nullable: true, Enum: []string{"fixture", "qualified-provider"}},
			phase5NullableID("lastGoodProofId", "LastGoodProofID"),
			FieldDefinition{JSONName: "retirementStatus", GoName: "RetirementStatus", Kind: ValueString, Required: true, Nullable: true, Enum: []string{"planned", "in-progress", "uncertain", "verified", "failed"}},
			phase5NullableDigest("retirementReceiptDigest", "RetirementReceiptDigest"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5Schema(backupRetentionLockSchemaID,
			phase5ID("pointId", "PointID"), phase5Digest("reasonDigest", "ReasonDigest"),
		),
		phase5Schema(backupRetentionLockCatalogSchemaID,
			phase5ID("repositoryId", "RepositoryID"), phase5Enum("repositoryClass", "RepositoryClass", "standard", "critical"),
			phase5Digest("sourceCoverageDigest", "SourceCoverageDigest"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5Positive("revision", "Revision"), phase5Bool("complete", "Complete"),
			FieldDefinition{JSONName: "locks", GoName: "Locks", Kind: ValueArray, Required: true, ItemRef: backupRetentionLockSchemaID, MaxItems: intPointer(256), UniqueItems: true},
		),
		phase5BackupSchema(recoveryPointSchemaID,
			phase5ID("pointId", "PointID"),
			phase5Enum("sourceKind", "SourceKind", "fixture", "local", "independent"),
			phase5Enum("proofClass", "ProofClass", "fixture", "live"),
			phase5Digest("contentDigest", "ContentDigest"), phase5Digest("manifestDigest", "ManifestDigest"),
			phase5Timestamp("createdAt", "CreatedAt"), phase5NullableTimestamp("verifiedAt", "VerifiedAt"),
			phase5Enum("verificationStatus", "VerificationStatus", "pending", "verified", "failed"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5IDs("dependencies", "Dependencies", 256),
		),
		phase5AuditSchema(auditCheckpointSchemaID,
			phase5ID("checkpointId", "CheckpointID"), phase5Positive("firstEventId", "FirstEventID"),
			phase5Positive("lastEventId", "LastEventID"), phase5Digest("chainDigest", "ChainDigest"),
			phase5ID("instanceId", "InstanceID"), phase5Positive("firstSegmentSequence", "FirstSegmentSequence"),
			phase5Positive("lastSegmentSequence", "LastSegmentSequence"),
			phase5ID("signerReferenceId", "SignerReferenceID"), phase5ID("signerMaterialVersion", "SignerMaterialVersion"),
			phase5NullableDigest("signatureDigest", "SignatureDigest"), phase5NullableID("publicKeyId", "PublicKeyID"),
			phase5NullableDigest("exportReceiptDigest", "ExportReceiptDigest"), phase5NullableDigest("independentReadDigest", "IndependentReadDigest"),
			phase5Enum("status", "Status", "pending", "signed", "export-pending", "anchored", "degraded", "incident"),
			phase5ID("reasonCode", "ReasonCode"), phase5Bool("preAnchor", "PreAnchor"),
			phase5NullableDigest("independentCopyDigest", "IndependentCopyDigest"),
			phase5Enum("sourceKind", "SourceKind", "fixture", "local", "independent"),
			phase5Enum("proofClass", "ProofClass", "fixture", "live"),
			phase5NullableTimestamp("verifiedAt", "VerifiedAt"),
			phase5Enum("verificationStatus", "VerificationStatus", "pending", "verified", "failed"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		{ID: restoreDependencyBindingSchemaID, Version: "1.1.0", ArtifactPath: schemaPath(restoreDependencyBindingSchemaID), Fields: []FieldDefinition{
			phase5ID("dependencyId", "DependencyID"), phase5Enum("kind", "Kind", "binary", "schema", "config", "image", "signature"), phase5Digest("digest", "Digest"),
		}},
		phase5RestoreSchema(restoreSourceBindingSchemaID,
			phase5ID("pointId", "PointID"), phase5Digest("pointDigest", "PointDigest"),
			phase5Digest("manifestDigest", "ManifestDigest"), phase5Digest("verificationDigest", "VerificationDigest"),
			phase5Enum("sourceClass", "SourceClass", "local", "off-site"), phase5ID("repositoryGenerationId", "RepositoryGenerationID"), phase5ID("keyReferenceId", "KeyReferenceID"),
			phase5Positive("declaredRpoSeconds", "DeclaredRPOSeconds"), phase5Timestamp("createdAt", "CreatedAt"),
			phase5Timestamp("verifiedAt", "VerifiedAt"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			FieldDefinition{JSONName: "dependencyDigests", GoName: "DependencyDigests", Kind: ValueArray, Required: true, ItemKind: ValueString, MaxItems: intPointer(256), UniqueItems: true},
			FieldDefinition{JSONName: "requiredDependencies", GoName: "RequiredDependencies", Kind: ValueArray, Required: true, ItemRef: restoreDependencyBindingSchemaID, MinItems: intPointer(1), MaxItems: intPointer(64), UniqueItems: true},
			phase5ID("targetReleaseBuildId", "TargetReleaseBuildID"), phase5Version("targetToolVersion", "TargetToolVersion"),
			FieldDefinition{JSONName: "targetSchemaVersion", GoName: "TargetSchemaVersion", Kind: ValueString, Required: true, Pattern: `^[1-9][0-9]*$`, MaxLength: intPointer(20)},
		),
		phase5RestoreSchema(restoreFenceItemSchemaID,
			phase5Enum("boundary", "Boundary", "host-service", "mesh", "ssh", "secret-resolver", "provider-mutation", "backup-writer", "audit-writer"),
			phase5ID("subjectId", "SubjectID"), phase5ID("targetId", "TargetID"), phase5ID("adapterId", "AdapterID"), phase5ID("formerIdentityId", "FormerIdentityID"),
			phase5ID("profileId", "ProfileID"), phase5Version("profileVersion", "ProfileVersion"), phase5ID("policyId", "PolicyID"), phase5Version("policyVersion", "PolicyVersion"),
			phase5ID("releaseBuildId", "ReleaseBuildID"), phase5Version("evaluatorVersion", "EvaluatorVersion"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			FieldDefinition{JSONName: "requiredEvidenceKinds", GoName: "RequiredEvidenceKinds", Kind: ValueArray, Required: true, ItemKind: ValueString, MinItems: intPointer(1), MaxItems: intPointer(16), UniqueItems: true}, phase5Bool("required", "Required"), phase5IDs("evidenceIds", "EvidenceIDs", 256),
			phase5Digest("evidenceDigest", "EvidenceDigest"), phase5NullableTimestamp("observedAt", "ObservedAt"), phase5Enum("status", "Status", "required", "verified", "blocked", "not-applicable"),
		),
		phase5RestoreSchema(restoreAuditDecisionSchemaID,
			phase5Nonnegative("localLastEventId", "LocalLastEventID"), phase5Nonnegative("independentLastEventId", "IndependentLastEventID"),
			phase5Digest("independentCheckpointDigest", "IndependentCheckpointDigest"), phase5Enum("strategy", "Strategy", "matched", "recovered-suffix", "accepted-loss"),
			phase5NullablePositive("lostFromEventId", "LostFromEventID"), phase5NullablePositive("lostThroughEventId", "LostThroughEventID"),
			phase5NullableTimestamp("lostFromTime", "LostFromTime"), phase5NullableTimestamp("lostThroughTime", "LostThroughTime"),
			phase5NullableID("humanAcknowledgementId", "HumanAcknowledgementID"), phase5Digest("decisionDigest", "DecisionDigest"),
		),
		phase5RestoreSchema(restoreCanaryResultSchemaID,
			phase5Bool("readVerified", "ReadVerified"), phase5Bool("oldEpochDenied", "OldEpochDenied"), phase5ID("noopRunId", "NoopRunID"),
			phase5ID("auditCheckpointId", "AuditCheckpointID"), phase5ID("backupPointId", "BackupPointID"), phase5Bool("formerWriterDenied", "FormerWriterDenied"),
			phase5Enum("status", "Status", "pending", "verified", "failed"), phase5NullableTimestamp("verifiedAt", "VerifiedAt"),
		),
		phase5RestoreSchema(restoreBindingSchemaID,
			FieldDefinition{JSONName: "source", GoName: "Source", Kind: ValueObject, Required: true, Ref: restoreSourceBindingSchemaID},
			phase5ID("pointId", "PointID"), phase5IDs("dependencyIds", "DependencyIDs", 256),
			FieldDefinition{JSONName: "targetIds", GoName: "TargetIDs", Kind: ValueArray, Required: true, ItemKind: ValueString, MinItems: intPointer(1), MaxItems: intPointer(64), UniqueItems: true},
			phase5Digest("targetDigest", "TargetDigest"), phase5ID("planId", "PlanID"), phase5Digest("planDigest", "PlanDigest"),
			phase5ID("humanAcknowledgementId", "HumanAcknowledgementID"),
			phase5Digest("fenceSetDigest", "FenceSetDigest"), phase5Digest("auditDecisionDigest", "AuditDecisionDigest"), phase5Digest("candidateDigest", "CandidateDigest"),
			phase5ID("formerHostId", "FormerHostID"), phase5ID("replacementHostId", "ReplacementHostID"), phase5ID("recoveryDraftId", "RecoveryDraftID"),
			phase5Digest("ciphertextFingerprint", "CiphertextFingerprint"), phase5Digest("sourceAdmissionDigest", "SourceAdmissionDigest"), phase5Digest("fenceQualificationDigest", "FenceQualificationDigest"),
			phase5ID("recoveryRunId", "RecoveryRunID"), phase5ID("recoveryStepId", "RecoveryStepID"), phase5ID("recoveryLeaseId", "RecoveryLeaseID"), phase5ID("recoveryChallengeId", "RecoveryChallengeID"), phase5ID("recoveryReceiptId", "RecoveryReceiptID"),
			phase5ID("canaryRunId", "CanaryRunID"), phase5ID("canaryStepId", "CanaryStepID"), phase5ID("canaryLeaseId", "CanaryLeaseID"), phase5ID("canaryChallengeId", "CanaryChallengeID"), phase5ID("canaryReceiptId", "CanaryReceiptID"), phase5Digest("canaryBindingDigest", "CanaryBindingDigest"),
			phase5ID("priorInstanceId", "PriorInstanceID"), phase5ID("newInstanceId", "NewInstanceID"),
			phase5Nonnegative("priorRecoveryEpoch", "PriorRecoveryEpoch"), phase5Positive("nextRecoveryEpoch", "NextRecoveryEpoch"),
			phase5Enum("status", "Status", "planned", "fenced", "restoring", "verification-required", "verified", "failed", "uncertain"),
		),
		phase5RestoreSchema(restoreVerificationSchemaID,
			FieldDefinition{JSONName: "source", GoName: "Source", Kind: ValueObject, Required: true, Ref: restoreSourceBindingSchemaID},
			phase5ID("planId", "PlanID"), phase5Digest("planDigest", "PlanDigest"), phase5ID("pointId", "PointID"),
			phase5Digest("targetDigest", "TargetDigest"), phase5Bool("fenceVerified", "FenceVerified"),
			phase5Bool("databaseVerified", "DatabaseVerified"), phase5Bool("auditVerified", "AuditVerified"),
			phase5NullableTimestamp("verifiedAt", "VerifiedAt"), phase5ID("priorInstanceId", "PriorInstanceID"), phase5ID("newInstanceId", "NewInstanceID"),
			phase5Nonnegative("priorRecoveryEpoch", "PriorRecoveryEpoch"), phase5Positive("nextRecoveryEpoch", "NextRecoveryEpoch"),
			phase5Digest("fenceSetDigest", "FenceSetDigest"), phase5Digest("auditDecisionDigest", "AuditDecisionDigest"), phase5Digest("candidateDigest", "CandidateDigest"),
			FieldDefinition{JSONName: "canary", GoName: "Canary", Kind: ValueObject, Required: true, Ref: restoreCanaryResultSchemaID},
			phase5Enum("status", "Status", "failed", "incomplete", "verified"),
		),
		phase5ScheduleSchema(scheduledJobPolicySchemaID,
			phase5ID("policyId", "PolicyID"), phase5Positive("revision", "Revision"),
			phase5ID("declarationId", "DeclarationID"), phase5Positive("declarationRevision", "DeclarationRevision"),
			phase5Enum("actionKind", "ActionKind", "gate-check", "observation-refresh", "backup-create", "backup-integrity-verify", "audit-checkpoint-export"),
			phase5ID("operationType", "OperationType"), phase5ID("adapterId", "AdapterID"),
			phase5IDs("exactSourceIds", "ExactSourceIDs", 64), phase5IDs("exactSubjectIds", "ExactSubjectIDs", 64), phase5IDs("exactTargetIds", "ExactTargetIDs", 64),
			phase5Positive("maximumWork", "MaximumWork"), phase5IDs("credentialReferenceIds", "CredentialReferenceIDs", 64),
			phase5Positive("grantRevision", "GrantRevision"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5Version("policyVersion", "PolicyVersion"), phase5Digest("retentionRuleDigest", "RetentionRuleDigest"),
			phase5Timestamp("anchorAt", "AnchorAt"), phase5Interval("intervalSeconds", "IntervalSeconds"), FieldDefinition{JSONName: "windowSeconds", GoName: "WindowSeconds", Kind: ValueInteger, Required: true, Minimum: int64Pointer(1800), Maximum: int64Pointer(604800)},
			phase5Enum("catchUp", "CatchUp", "none", "latest"), phase5Enum("concurrency", "Concurrency", "forbid"),
			phase5Positive("maxAttempts", "MaxAttempts"), phase5Positive("initialBackoffSeconds", "InitialBackoffSeconds"), phase5Positive("maximumBackoffSeconds", "MaximumBackoffSeconds"),
			phase5Timestamp("expiresAt", "ExpiresAt"), phase5Bool("enabled", "Enabled"),
		),
		phase5ScheduleSchema(scheduledPolicyDraftSubmissionSchemaID,
			phase5ID("draftId", "DraftID"), phase5ID("policyId", "PolicyID"), phase5Positive("policyRevision", "PolicyRevision"),
			phase5Digest("policyDigest", "PolicyDigest"), phase5Enum("status", "Status", "draft"),
			phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5ScheduleSchema(scheduledJobSchemaID,
			phase5ID("jobId", "JobID"), phase5ID("policyId", "PolicyID"),
			phase5Positive("policyRevision", "PolicyRevision"), phase5Timestamp("scheduledAt", "ScheduledAt"), phase5Positive("attempt", "Attempt"),
			phase5NullableID("planId", "PlanID"), phase5NullableID("runId", "RunID"),
			phase5Enum("status", "Status", "queued", "blocked", "skipped", "running", "retry-wait", "cancelled", "failed", "succeeded", "uncertain"), phase5ID("reasonCode", "ReasonCode"),
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

// Credential lifecycle is a scoped additive revision introduced by issue #125.
// Its request and submission sources carry only exact metadata; they never
// accept a credential value or a caller-authored ciphertext fingerprint.
func phase5LifecycleSchema(identifier string, fields ...FieldDefinition) SchemaDefinition {
	schema := phase5Schema(identifier, fields...)
	schema.Version = "1.2.0"
	schema.Fields[1].Enum = []string{"1.2.0"}
	return schema
}

func phase5LifecycleRequest(identifier string, fields ...FieldDefinition) SchemaDefinition {
	schema := phase5Request(identifier, fields...)
	schema.Version = "1.3.0"
	schema.Fields[1].Enum = []string{"1.3.0"}
	return schema
}

func phase5NullableNonnegative(name, goName string) FieldDefinition {
	field := phase5Nonnegative(name, goName)
	field.Nullable = true
	return field
}

func phase5BoundedNonnegative(name, goName string, maximum int64) FieldDefinition {
	field := phase5Nonnegative(name, goName)
	field.Maximum = int64Pointer(maximum)
	return field
}

func phase5LifecycleAction() FieldDefinition {
	return phase5Enum("action", "Action", "credential.stage", "credential.activate", "credential.rotate", "credential.revoke", "credential.recover")
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
		phase5BackupVerifyRequest(
			phase5ID("jobId", "JobID"), phase5ID("pointId", "PointID"),
			phase5ID("planId", "PlanID"), phase5Digest("planDigest", "PlanDigest"),
			phase5ID("humanAcknowledgementId", "HumanAcknowledgementID"),
		),
		phase5RestoreRequest(restoreRequestSchemaID,
			FieldDefinition{JSONName: "source", GoName: "Source", Kind: ValueObject, Required: true, Ref: restoreSourceBindingSchemaID},
			FieldDefinition{JSONName: "fences", GoName: "Fences", Kind: ValueArray, Required: true, ItemRef: restoreFenceItemSchemaID, MinItems: intPointer(1), MaxItems: intPointer(7), UniqueItems: true},
			FieldDefinition{JSONName: "auditDecision", GoName: "AuditDecision", Kind: ValueObject, Required: true, Ref: restoreAuditDecisionSchemaID},
			phase5ID("pointId", "PointID"), phase5IDs("dependencyIds", "DependencyIDs", 256),
			FieldDefinition{JSONName: "targetIds", GoName: "TargetIDs", Kind: ValueArray, Required: true, ItemKind: ValueString, MinItems: intPointer(1), MaxItems: intPointer(64), UniqueItems: true},
			phase5ID("priorInstanceId", "PriorInstanceID"), phase5ID("newInstanceId", "NewInstanceID"),
			phase5Nonnegative("priorRecoveryEpoch", "PriorRecoveryEpoch"), phase5Positive("nextRecoveryEpoch", "NextRecoveryEpoch"),
			phase5Digest("fenceSetDigest", "FenceSetDigest"), phase5Digest("auditDecisionDigest", "AuditDecisionDigest"), phase5Digest("candidateDigest", "CandidateDigest"),
			phase5ID("formerHostId", "FormerHostID"), phase5ID("replacementHostId", "ReplacementHostID"), phase5ID("recoveryDraftId", "RecoveryDraftID"),
			phase5Digest("ciphertextFingerprint", "CiphertextFingerprint"), phase5Digest("sourceAdmissionDigest", "SourceAdmissionDigest"), phase5Digest("fenceQualificationDigest", "FenceQualificationDigest"),
			phase5ID("recoveryRunId", "RecoveryRunID"), phase5ID("recoveryStepId", "RecoveryStepID"), phase5ID("recoveryLeaseId", "RecoveryLeaseID"), phase5ID("recoveryChallengeId", "RecoveryChallengeID"), phase5ID("recoveryReceiptId", "RecoveryReceiptID"),
			phase5ID("canaryRunId", "CanaryRunID"), phase5ID("canaryStepId", "CanaryStepID"), phase5ID("canaryLeaseId", "CanaryLeaseID"), phase5ID("canaryChallengeId", "CanaryChallengeID"), phase5ID("canaryReceiptId", "CanaryReceiptID"), phase5Digest("canaryBindingDigest", "CanaryBindingDigest"),
		),
		phase5Request(browserRestoreDraftRequestSchemaID,
			phase5ID("pointId", "PointID"),
		),
		phase5RestoreRequest(restoreRunRequestSchemaID,
			FieldDefinition{JSONName: "source", GoName: "Source", Kind: ValueObject, Required: true, Ref: restoreSourceBindingSchemaID},
			phase5ID("pointId", "PointID"), phase5ID("planId", "PlanID"), phase5Digest("planDigest", "PlanDigest"),
			phase5ID("humanAcknowledgementId", "HumanAcknowledgementID"),
			phase5Digest("fenceSetDigest", "FenceSetDigest"), phase5Digest("auditDecisionDigest", "AuditDecisionDigest"), phase5Digest("candidateDigest", "CandidateDigest"),
			phase5ID("priorInstanceId", "PriorInstanceID"), phase5ID("newInstanceId", "NewInstanceID"),
			phase5Nonnegative("priorRecoveryEpoch", "PriorRecoveryEpoch"), phase5Positive("nextRecoveryEpoch", "NextRecoveryEpoch"),
			phase5ID("recoveryRunId", "RecoveryRunID"), phase5ID("recoveryStepId", "RecoveryStepID"), phase5ID("recoveryLeaseId", "RecoveryLeaseID"), phase5ID("recoveryChallengeId", "RecoveryChallengeID"), phase5ID("recoveryReceiptId", "RecoveryReceiptID"),
			phase5ID("canaryRunId", "CanaryRunID"), phase5ID("canaryStepId", "CanaryStepID"), phase5ID("canaryLeaseId", "CanaryLeaseID"), phase5ID("canaryChallengeId", "CanaryChallengeID"), phase5ID("canaryReceiptId", "CanaryReceiptID"), phase5Digest("canaryBindingDigest", "CanaryBindingDigest"),
		),
		phase5RestoreRequest(restoreVerifyRequestSchemaID,
			FieldDefinition{JSONName: "source", GoName: "Source", Kind: ValueObject, Required: true, Ref: restoreSourceBindingSchemaID},
			phase5ID("pointId", "PointID"), phase5ID("planId", "PlanID"), phase5Digest("planDigest", "PlanDigest"),
			phase5ID("priorInstanceId", "PriorInstanceID"), phase5ID("newInstanceId", "NewInstanceID"), phase5Nonnegative("priorRecoveryEpoch", "PriorRecoveryEpoch"), phase5Positive("nextRecoveryEpoch", "NextRecoveryEpoch"),
			phase5Digest("fenceSetDigest", "FenceSetDigest"), phase5Digest("auditDecisionDigest", "AuditDecisionDigest"), phase5Digest("candidateDigest", "CandidateDigest"),
		),
		phase5ScheduleRequest(
			phase5ID("policyId", "PolicyID"), phase5Positive("policyRevision", "PolicyRevision"),
			phase5ID("occurrenceToken", "OccurrenceToken"), phase5Timestamp("observedAt", "ObservedAt"),
		),
		phase5ScheduleSchema(scheduledJobCancelRequestSchemaID, phase5ID("idempotencyKey", "IdempotencyKey")),
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
		phase5BackupRequest(backupPolicyDraftRequestSchemaID,
			FieldDefinition{JSONName: "policy", GoName: "Policy", Kind: ValueObject, Required: true, Ref: backupPolicySchemaID},
		),
		phase5BackupRequest(backupRetentionLockDraftRequestID,
			FieldDefinition{JSONName: "catalog", GoName: "Catalog", Kind: ValueObject, Required: true, Ref: backupRetentionLockCatalogSchemaID},
		),
		phase5BackupSchema(backupRetentionLockDraftSubmissionID,
			phase5ID("draftId", "DraftID"), phase5ID("changeId", "ChangeID"), phase5ID("operationId", "OperationID"),
			phase5Digest("catalogDigest", "CatalogDigest"), phase5Enum("status", "Status", "draft"),
			phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5BackupRequest(backupRetirementDraftRequestID,
			phase5Enum("repositoryClass", "RepositoryClass", "standard", "critical"),
			phase5ID("referenceId", "ReferenceID"), phase5Enum("resolverId", "ResolverID", "native-systemd"),
			phase5ID("materialVersion", "MaterialVersion"),
		),
		phase5BackupSchema(backupRetirementDraftSubmissionID,
			phase5ID("draftId", "DraftID"), phase5ID("changeId", "ChangeID"), phase5ID("operationId", "OperationID"),
			phase5Digest("selectionDigest", "SelectionDigest"), phase5Digest("credentialManifestDigest", "CredentialManifestDigest"),
			phase5IDs("targetPointIds", "TargetPointIDs", 256), phase5IDs("survivorPointIds", "SurvivorPointIDs", 256),
			phase5Enum("status", "Status", "draft"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5BackupSchema(backupOffsiteRetirementDryRunRequestID,
			phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5Digest("selectionDigest", "SelectionDigest"), phase5ID("oneOwnerProofId", "OneOwnerProofID"),
			phase5ID("lockAdminReferenceId", "LockAdminReferenceID"), phase5ID("retentionReferenceId", "RetentionReferenceID"),
		),
		phase5Schema(backupOffsiteRetirementRuleID,
			phase5ID("ruleId", "RuleID"),
			FieldDefinition{JSONName: "prefix", GoName: "Prefix", Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(512)},
		),
		phase5Schema(backupOffsiteRetirementObjectID,
			FieldDefinition{JSONName: "key", GoName: "Key", Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(1024)},
			phase5Digest("digest", "Digest"), phase5Nonnegative("bytes", "Bytes"),
		),
		phase5Schema(backupOffsiteRetirementSurvivorBindingID,
			phase5ID("pointId", "PointID"), phase5ID("generationId", "GenerationID"), phase5ID("referenceId", "ReferenceID"), phase5Digest("dependencyDigest", "DependencyDigest"),
		),
		phase5BackupSchema(backupOffsiteRetirementDryRunDataID,
			phase5Digest("intentDigest", "IntentDigest"), phase5Digest("selectionDigest", "SelectionDigest"),
			phase5ID("generationId", "GenerationID"), phase5ID("pointId", "PointID"), phase5ID("bucketId", "BucketID"),
			phase5Digest("ruleSetDigest", "RuleSetDigest"), phase5Digest("survivorRuleDigest", "SurvivorRuleDigest"), phase5Digest("manifestDigest", "ManifestDigest"), phase5Digest("catalogDigest", "CatalogDigest"), phase5Digest("inventoryDigest", "InventoryDigest"),
			phase5ID("oneOwnerProofId", "OneOwnerProofID"),
			phase5ID("lockAdminReferenceId", "LockAdminReferenceID"), phase5Digest("lockAdminFingerprint", "LockAdminFingerprint"),
			phase5ID("retentionReferenceId", "RetentionReferenceID"), phase5Digest("retentionFingerprint", "RetentionFingerprint"),
			phase5Digest("g008BundleDigest", "G008BundleDigest"), phase5Digest("qualificationDigest", "QualificationDigest"), phase5Digest("putCutoffDigest", "PutCutoffDigest"), phase5Digest("multipartCutoffDigest", "MultipartCutoffDigest"), phase5Digest("exclusiveAdminDigest", "ExclusiveAdminDigest"),
			phase5IDs("survivorPointIds", "SurvivorPointIDs", 256), phase5IDs("survivorKeyReferenceIds", "SurvivorKeyReferenceIDs", 256),
			FieldDefinition{JSONName: "rules", GoName: "Rules", Kind: ValueArray, Required: true, ItemRef: backupOffsiteRetirementRuleID, MinItems: intPointer(5), MaxItems: intPointer(5), UniqueItems: true},
			FieldDefinition{JSONName: "objects", GoName: "Objects", Kind: ValueArray, Required: true, ItemRef: backupOffsiteRetirementObjectID, MaxItems: intPointer(1000000)},
			FieldDefinition{JSONName: "survivorBindings", GoName: "SurvivorBindings", Kind: ValueArray, Required: true, ItemRef: backupOffsiteRetirementSurvivorBindingID, MaxItems: intPointer(256), UniqueItems: true},
			phase5Nonnegative("objectCount", "ObjectCount"), phase5Nonnegative("expectedReclaimBytes", "ExpectedReclaimBytes"), phase5Nonnegative("retainedBytes", "RetainedBytes"), phase5Nonnegative("maxWorkObjects", "MaxWorkObjects"), phase5Nonnegative("maxMutationBytes", "MaxMutationBytes"),
			phase5Nonnegative("preRuleCount", "PreRuleCount"), phase5Nonnegative("survivorRuleCount", "SurvivorRuleCount"), phase5Nonnegative("sourceRevision", "SourceRevision"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5BackupRequest(backupOffsiteRetirementStageRequestID,
			phase5Digest("selectionDigest", "SelectionDigest"), phase5ID("planId", "PlanID"), phase5Digest("planDigest", "PlanDigest"),
			phase5ID("oneOwnerProofId", "OneOwnerProofID"), phase5ID("lockAdminReferenceId", "LockAdminReferenceID"), phase5ID("retentionReferenceId", "RetentionReferenceID"),
			phase5Digest("credentialBindingDigest", "CredentialBindingDigest"),
		),
		phase5BackupSchema(backupOffsiteRetirementStageSubmissionID,
			phase5ID("intentId", "IntentID"), phase5ID("generationId", "GenerationID"), phase5ID("pointId", "PointID"),
			phase5Digest("ruleSetDigest", "RuleSetDigest"), phase5Digest("survivorRuleDigest", "SurvivorRuleDigest"),
			phase5Nonnegative("preRuleCount", "PreRuleCount"), phase5Nonnegative("survivorRuleCount", "SurvivorRuleCount"),
			phase5IDs("survivorPointIds", "SurvivorPointIDs", 256), phase5Nonnegative("expectedReclaimBytes", "ExpectedReclaimBytes"),
			phase5Enum("status", "Status", "staged"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5BackupSchema(backupPolicyDraftSubmissionSchemaID,
			phase5ID("draftId", "DraftID"), phase5ID("policyId", "PolicyID"),
			phase5Digest("policyDigest", "PolicyDigest"),
			phase5Enum("status", "Status", "draft"),
			phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5Schema(credentialNativeConsumerSchemaID,
			phase5ID("consumerId", "ConsumerID"), phase5ID("targetId", "TargetID"),
			FieldDefinition{JSONName: "hostMachineId", GoName: "HostMachineID", Kind: ValueString, Required: true, Pattern: `^[0-9a-f]{32}$`},
			FieldDefinition{JSONName: "unitName", GoName: "UnitName", Kind: ValueString, Required: true, Pattern: `^[a-z0-9][a-z0-9_.@-]{0,119}\.service$`},
			phase5BoundedNonnegative("serviceUid", "ServiceUID", 4294967295), phase5BoundedNonnegative("serviceGid", "ServiceGID", 4294967295),
			phase5ID("profileId", "ProfileID"), phase5ID("roleId", "RoleID"),
		),
		phase5Schema(credentialNativeDeniedReaderID,
			phase5ID("consumerId", "ConsumerID"), phase5ID("targetId", "TargetID"),
			FieldDefinition{JSONName: "hostMachineId", GoName: "HostMachineID", Kind: ValueString, Required: true, Pattern: `^[0-9a-f]{32}$`},
			phase5BoundedNonnegative("readerUid", "ReaderUID", 4294967295), phase5BoundedNonnegative("readerGid", "ReaderGID", 4294967295),
			phase5ID("profileId", "ProfileID"), phase5ID("roleId", "RoleID"),
		),
		phase5LifecycleRequest(credentialLifecycleRequestSchemaID,
			phase5LifecycleAction(),
			phase5NullableID("draftId", "DraftID"),
			phase5ID("referenceId", "ReferenceID"),
			phase5IDs("consumerIds", "ConsumerIDs", 64),
			phase5IDs("requiredDeniedConsumerIds", "RequiredDeniedConsumerIDs", 64),
			FieldDefinition{JSONName: "nativeConsumers", GoName: "NativeConsumers", Kind: ValueArray, Required: false, Nullable: true, ItemRef: credentialNativeConsumerSchemaID, MaxItems: intPointer(64)},
			FieldDefinition{JSONName: "nativeDeniedReaders", GoName: "NativeDeniedReaders", Kind: ValueArray, Required: false, Nullable: true, ItemRef: credentialNativeDeniedReaderID, MaxItems: intPointer(64)},
			phase5ID("materialVersion", "MaterialVersion"),
			phase5NullableID("priorMaterialVersion", "PriorMaterialVersion"),
			phase5ID("resolverId", "ResolverID"),
			phase5ID("targetId", "TargetID"),
			phase5BoundedNonnegative("overlapSeconds", "OverlapSeconds", 3600),
			phase5NullableNonnegative("priorRecoveryEpoch", "PriorRecoveryEpoch"),
			phase5NullableDigest("custodyProofDigest", "CustodyProofDigest"),
			phase5NullableDigest("formerControllerFenceDigest", "FormerControllerFenceDigest"),
		),
		phase5LifecycleSchema(credentialLifecycleSubmissionID,
			phase5ID("changeId", "ChangeID"), phase5ID("operationId", "OperationID"),
			phase5ID("referenceId", "ReferenceID"), phase5LifecycleAction(),
			phase5Enum("status", "Status", "draft"),
			phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
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
		phase5BackupStatusSchema(
			FieldDefinition{JSONName: "policies", GoName: "Policies", Kind: ValueArray, Required: true, ItemRef: backupPolicySchemaID, MaxItems: intPointer(256)},
			FieldDefinition{JSONName: "jobs", GoName: "Jobs", Kind: ValueArray, Required: true, ItemRef: backupJobSchemaID, MaxItems: intPointer(256)},
			FieldDefinition{JSONName: "verifications", GoName: "Verifications", Kind: ValueArray, Required: true, ItemRef: backupVerificationAttemptSchemaID, MaxItems: intPointer(256)},
			FieldDefinition{JSONName: "lastGood", GoName: "LastGood", Kind: ValueArray, Required: true, ItemRef: backupLastGoodSchemaID, MaxItems: intPointer(16)},
			FieldDefinition{JSONName: "retirements", GoName: "Retirements", Kind: ValueArray, Required: true, ItemRef: backupLocalRetirementStatusSchemaID, MaxItems: intPointer(256)},
			FieldDefinition{JSONName: "offsite", GoName: "Offsite", Kind: ValueArray, Required: true, ItemRef: backupOffsiteStatusSchemaID, MaxItems: intPointer(256)},
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5Schema(auditCheckpointListDataSchemaID,
			FieldDefinition{JSONName: "checkpoints", GoName: "Checkpoints", Kind: ValueArray, Required: true, ItemRef: auditCheckpointSchemaID, MaxItems: intPointer(256)},
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5AuditSchema(auditVerificationDataSchemaID,
			phase5Enum("status", "Status", "pending", "anchored", "degraded", "incident"),
			phase5ID("instanceId", "InstanceID"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5Digest("localDigest", "LocalDigest"), phase5NullableDigest("independentDigest", "IndependentDigest"),
			phase5Bool("independentMatch", "IndependentMatch"), phase5Nonnegative("lastAnchoredSequence", "LastAnchoredSequence"),
			phase5ID("reasonCode", "ReasonCode"), phase5Bool("preAnchor", "PreAnchor"),
		),
		phase5Schema(browserRestoreStatusSchemaID,
			phase5ID("pointId", "PointID"), phase5ID("planId", "PlanID"), phase5Digest("planDigest", "PlanDigest"),
			phase5Digest("targetDigest", "TargetDigest"),
			phase5Enum("status", "Status", "planned", "fenced", "restoring", "verification-required", "verified", "failed", "uncertain"),
			phase5ID("reasonCode", "ReasonCode"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			phase5Enum("verificationStatus", "VerificationStatus", "pending", "incomplete", "verified", "failed"),
			FieldDefinition{JSONName: "safeNextAction", GoName: "SafeNextAction", Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(256)},
		),
		phase5Schema(browserBackupStatusDataSchemaID,
			phase5Enum("status", "Status", "empty", "pending", "healthy", "stale", "failed", "unavailable", "recovery-required"),
			phase5ID("reasonCode", "ReasonCode"), phase5Enum("sourceKind", "SourceKind", "none", "fixture", "local", "independent"),
			phase5Enum("proofClass", "ProofClass", "none", "fixture", "live"), phase5NullableID("lastGoodPointId", "LastGoodPointID"),
			phase5Bool("recoveryRequired", "RecoveryRequired"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			FieldDefinition{JSONName: "safeNextAction", GoName: "SafeNextAction", Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(256)},
		),
		phase5Schema(browserRecoveryPointSchemaID,
			phase5ID("pointId", "PointID"), phase5Enum("sourceKind", "SourceKind", "fixture", "local", "independent"),
			phase5Enum("proofClass", "ProofClass", "fixture", "live"), phase5Digest("contentDigest", "ContentDigest"), phase5Digest("manifestDigest", "ManifestDigest"),
			phase5Timestamp("createdAt", "CreatedAt"), phase5NullableTimestamp("verifiedAt", "VerifiedAt"),
			phase5Enum("verificationStatus", "VerificationStatus", "pending", "verified", "failed"), phase5ID("reasonCode", "ReasonCode"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5Schema(browserAuditCheckpointSchemaID,
			phase5ID("checkpointId", "CheckpointID"), phase5Positive("firstEventId", "FirstEventID"), phase5Positive("lastEventId", "LastEventID"),
			phase5Digest("chainDigest", "ChainDigest"), phase5Enum("status", "Status", "pending", "signed", "export-pending", "anchored", "degraded", "incident"),
			phase5ID("reasonCode", "ReasonCode"), phase5Enum("sourceKind", "SourceKind", "fixture", "local", "independent"), phase5Enum("proofClass", "ProofClass", "fixture", "live"),
			phase5NullableTimestamp("verifiedAt", "VerifiedAt"), phase5Enum("verificationStatus", "VerificationStatus", "pending", "verified", "failed"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5Schema(browserAuditVerificationDataSchemaID,
			phase5Enum("status", "Status", "pending", "anchored", "degraded", "incident"), phase5ID("reasonCode", "ReasonCode"),
			phase5Enum("sourceKind", "SourceKind", "none", "independent"), phase5Enum("proofClass", "ProofClass", "none", "live"),
			phase5Bool("independentMatch", "IndependentMatch"), phase5Nonnegative("lastAnchoredSequence", "LastAnchoredSequence"), phase5Bool("preAnchor", "PreAnchor"),
			phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
			FieldDefinition{JSONName: "safeNextAction", GoName: "SafeNextAction", Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(256)},
		),
		phase5Schema(browserRestoreDraftSubmissionSchemaID,
			phase5ID("draftId", "DraftID"), phase5ID("changeId", "ChangeID"), phase5ID("pointId", "PointID"), phase5Enum("status", "Status", "draft"),
			phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5Schema(browserScheduledJobPolicySchemaID,
			phase5ID("policyId", "PolicyID"), phase5Positive("revision", "Revision"), phase5Enum("actionKind", "ActionKind", "gate-check", "observation-refresh", "backup-create", "backup-integrity-verify", "audit-checkpoint-export"),
			phase5Bool("enabled", "Enabled"), phase5Enum("status", "Status", "active", "disabled"), phase5ID("reasonCode", "ReasonCode"),
			phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5Schema(browserScheduledJobSchemaID,
			phase5ID("jobId", "JobID"), phase5ID("policyId", "PolicyID"), phase5Positive("policyRevision", "PolicyRevision"),
			phase5Enum("status", "Status", "queued", "blocked", "skipped", "running", "retry-wait", "succeeded", "cancelled", "failed", "uncertain"), phase5ID("reasonCode", "ReasonCode"),
			phase5Timestamp("scheduledAt", "ScheduledAt"), phase5Timestamp("windowClosesAt", "WindowClosesAt"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
		phase5PageSchema(browserRecoveryPointListDataSchemaID, browserRecoveryPointSchemaID),
		phase5PageSchema(browserAuditCheckpointListDataSchemaID, browserAuditCheckpointSchemaID),
		phase5PageSchema(browserRestoreStatusListDataSchemaID, browserRestoreStatusSchemaID),
		phase5PageSchema(browserScheduledJobPolicyListDataSchemaID, browserScheduledJobPolicySchemaID),
		phase5PageSchema(browserScheduledJobListDataSchemaID, browserScheduledJobSchemaID),
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
		{ID: "api.v1.credential-lifecycle-drafts.create", Method: "POST", Path: "/api/v1/credential-lifecycle-drafts", RequestSchema: credentialLifecycleRequestSchemaID, DataSchema: credentialLifecycleSubmissionID, Availability: AvailabilityAvailable, OwnerPhase: "5", Stream: StreamFinite, Audiences: []EndpointAudience{AudienceOperator}},
		{ID: "api.v1.gate-profile-drafts.create", Method: "POST", Path: "/api/v1/gates/profile-drafts", RequestSchema: gateProfileDraftRequestSchemaID, DataSchema: gateProfileDraftSubmissionSchemaID, Availability: AvailabilityAvailable, OwnerPhase: "5", Stream: StreamFinite, Audiences: []EndpointAudience{AudienceOperator}},
		phase5AvailableGateEndpoint("api.v1.gates.list", "GET", "/api/v1/gates", "", gateListDataSchemaID, true),
		phase5AvailableGateEndpoint("api.v1.gates.get", "GET", "/api/v1/gates/{gateId}", "", gateViewSchemaID, true),
		phase5AvailableGateEndpoint("api.v1.gates.check", "POST", "/api/v1/gates/{gateId}/check", gateCheckRequestSchemaID, gateEvaluationSchemaID, true),
		phase5AvailableGateEndpoint("api.v1.gate-evidence.create", "POST", "/api/v1/gates/{gateId}/evidence", gateEvidenceRequestSchemaID, gateEvidenceSubmissionSchemaID, true),
		phase5Endpoint("api.v1.credential-references.get", "GET", "/api/v1/credential-references/{referenceId}", "", credentialReferenceSchemaID, false),
		phase5Endpoint("api.v1.credential-resolution-records.get", "GET", "/api/v1/credential-resolution-records/{recordId}", "", credentialResolutionRecordSchemaID, false),
		{ID: "api.v1.credential-references.import-stream", Method: "POST", Path: "/api/v1/credential-references/{referenceId}/import-stream", RequestSchema: credentialImportRequestSchemaID, DataSchema: credentialImportSubmissionSchemaID, Availability: AvailabilityAvailable, OwnerPhase: "5", Stream: StreamFinite, Audiences: []EndpointAudience{AudienceOperator}, RequestEncoding: "binary", TransportScope: "local", MaxRequestBytes: 4096},
		{ID: "api.v1.backup-policy-drafts.create", Method: "POST", Path: "/api/v1/backups/policies/drafts", RequestSchema: backupPolicyDraftRequestSchemaID, DataSchema: backupPolicyDraftSubmissionSchemaID, Availability: AvailabilityAvailable, OwnerPhase: "5", Stream: StreamFinite, Audiences: []EndpointAudience{AudienceOperator}},
		{ID: "api.v1.backup-retention-lock-drafts.create", Method: "POST", Path: "/api/v1/backups/retention-locks/drafts", RequestSchema: backupRetentionLockDraftRequestID, DataSchema: backupRetentionLockDraftSubmissionID, Availability: AvailabilityAvailable, OwnerPhase: "5", Stream: StreamFinite, Audiences: []EndpointAudience{AudienceOperator}},
		{ID: "api.v1.backup-retirement-drafts.create", Method: "POST", Path: "/api/v1/backups/retirements/drafts", RequestSchema: backupRetirementDraftRequestID, DataSchema: backupRetirementDraftSubmissionID, Availability: AvailabilityAvailable, OwnerPhase: "5", Stream: StreamFinite, Audiences: []EndpointAudience{AudienceOperator}},
		{ID: "api.v1.backup-offsite-retirements.stage", Method: "POST", Path: "/api/v1/backups/offsite-retirements/stage", RequestSchema: backupOffsiteRetirementStageRequestID, DataSchema: backupOffsiteRetirementStageSubmissionID, Availability: AvailabilityAvailable, OwnerPhase: "5", Stream: StreamFinite, Audiences: []EndpointAudience{AudienceOperator}},
		{ID: "api.v1.backup-offsite-retirements.dry-run", Method: "POST", Path: "/api/v1/backups/offsite-retirements/dry-run", RequestSchema: backupOffsiteRetirementDryRunRequestID, DataSchema: backupOffsiteRetirementDryRunDataID, Availability: AvailabilityAvailable, OwnerPhase: "5", Stream: StreamFinite, Audiences: []EndpointAudience{AudienceOperator}},
		phase5AvailableGateEndpoint("api.v1.backups.status", "GET", "/api/v1/backups/status", "", browserBackupStatusDataSchemaID, true),
		phase5AvailableGateEndpoint("api.v1.backup-jobs.create", "POST", "/api/v1/backup-policies/{policyId}/jobs", backupRunRequestSchemaID, backupJobSchemaID, false),
		phase5AvailableGateEndpoint("api.v1.backup-verifications.create", "POST", "/api/v1/recovery-points/{pointId}/verifications", backupVerifyRequestSchemaID, backupJobSchemaID, false),
		{ID: "api.v1.recovery-points.list", Method: "GET", Path: "/api/v1/recovery-points", Availability: AvailabilityAvailable, OwnerPhase: "5", QuerySchema: apiPageQuerySchemaID, DataSchema: browserRecoveryPointListDataSchemaID, Stream: StreamFinite, Audiences: []EndpointAudience{AudienceBrowser, AudienceOperator}},
		{ID: "api.v1.audit-checkpoints.list", Method: "GET", Path: "/api/v1/audit-checkpoints", Availability: AvailabilityAvailable, OwnerPhase: "5", QuerySchema: apiPageQuerySchemaID, DataSchema: browserAuditCheckpointListDataSchemaID, Stream: StreamFinite, Audiences: []EndpointAudience{AudienceBrowser, AudienceOperator}},
		phase5AvailableGateEndpoint("api.v1.audit-checkpoints.create", "POST", "/api/v1/audit-checkpoints", auditCheckpointRequestSchemaID, auditCheckpointSchemaID, false),
		phase5AvailableGateEndpoint("api.v1.audit-history.verification", "GET", "/api/v1/audit-history/verification", "", browserAuditVerificationDataSchemaID, true),
		phase5AvailableGateEndpoint("api.v1.restore-drafts.create", "POST", "/api/v1/recovery-points/{pointId}/restore-drafts", browserRestoreDraftRequestSchemaID, browserRestoreDraftSubmissionSchemaID, true),
		phase5AvailableGateEndpoint("api.v1.restores.plan", "POST", "/api/v1/recovery-points/{pointId}/restore-plans", restoreRequestSchemaID, restoreBindingSchemaID, false),
		{ID: "api.v1.restores.list", Method: "GET", Path: "/api/v1/restore-plans", Availability: AvailabilityAvailable, OwnerPhase: "5", QuerySchema: apiPageQuerySchemaID, DataSchema: browserRestoreStatusListDataSchemaID, Stream: StreamFinite, Audiences: []EndpointAudience{AudienceBrowser, AudienceOperator}},
		phase5AvailableGateEndpoint("api.v1.restores.run", "POST", "/api/v1/restore-plans/{planId}/runs", restoreRunRequestSchemaID, restoreBindingSchemaID, false),
		phase5AvailableGateEndpoint("api.v1.restores.verify", "POST", "/api/v1/restore-plans/{planId}/verifications", restoreVerifyRequestSchemaID, restoreVerificationSchemaID, false),
		{ID: "api.v1.scheduled-job-policies.list", Method: "GET", Path: "/api/v1/scheduled-job-policies", Availability: AvailabilityAvailable, OwnerPhase: "5", QuerySchema: apiPageQuerySchemaID, DataSchema: browserScheduledJobPolicyListDataSchemaID, Stream: StreamFinite, Audiences: []EndpointAudience{AudienceBrowser, AudienceOperator}},
		phase5AvailableGateEndpoint("api.v1.scheduled-job-policies.get", "GET", "/api/v1/scheduled-job-policies/{policyId}", "", browserScheduledJobPolicySchemaID, true),
		phase5AvailableGateEndpoint("api.v1.scheduled-job-policies.drafts.create", "POST", "/api/v1/scheduled-job-policies/drafts", scheduledJobPolicySchemaID, scheduledPolicyDraftSubmissionSchemaID, false),
		{ID: "api.v1.scheduled-occurrences.create", Method: "POST", Path: "/api/v1/scheduled-job-policies/{policyId}/occurrences", RequestSchema: scheduledJobRequestSchemaID, DataSchema: scheduledJobSchemaID, Availability: AvailabilityAvailable, OwnerPhase: "5", Stream: StreamFinite, Audiences: []EndpointAudience{AudienceOperator}, TransportScope: "local"},
		{ID: "api.v1.scheduled-jobs.list", Method: "GET", Path: "/api/v1/scheduled-jobs", Availability: AvailabilityAvailable, OwnerPhase: "5", QuerySchema: apiPageQuerySchemaID, DataSchema: browserScheduledJobListDataSchemaID, Stream: StreamFinite, Audiences: []EndpointAudience{AudienceBrowser, AudienceOperator}},
		{ID: "api.v1.scheduled-jobs.cancel", Method: "POST", Path: "/api/v1/scheduled-jobs/{jobId}/cancel", RequestSchema: scheduledJobCancelRequestSchemaID, DataSchema: scheduledJobSchemaID, Availability: AvailabilityAvailable, OwnerPhase: "5", Stream: StreamFinite, Audiences: []EndpointAudience{AudienceOperator}, TransportScope: "local"},
	}
}

func phase5CommandSchemas(path string) (request string, data string) {
	switch path {
	case "audit", "audit checkpoints":
		return "", browserAuditCheckpointListDataSchemaID
	case "audit verify":
		return "", browserAuditVerificationDataSchemaID
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
		return "", browserBackupStatusDataSchemaID
	case "schedule list":
		return "", browserScheduledJobPolicyListDataSchemaID
	case "schedule inspect":
		return "", browserScheduledJobPolicySchemaID
	case "backup retention-locks draft":
		return backupRetentionLockDraftRequestID, backupRetentionLockDraftSubmissionID
	case "backup retirement draft":
		return backupRetirementDraftRequestID, backupRetirementDraftSubmissionID
	case "backup offsite-retirement stage":
		return backupOffsiteRetirementStageRequestID, backupOffsiteRetirementStageSubmissionID
	case "backup offsite-retirement dry-run":
		return backupOffsiteRetirementDryRunRequestID, backupOffsiteRetirementDryRunDataID
	case "recovery witness collect":
		return "", recoveryWitnessCollectionDataSchemaID
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
	return []TransitionDefinition{{From: "queued", To: "running"}, {From: "queued", To: "failed"}, {From: "running", To: "pending"}, {From: "running", To: "failed"}, {From: "running", To: "uncertain"}, {From: "pending", To: "verified"}, {From: "pending", To: "failed"}}
}

func phase5RestoreTransitions() []TransitionDefinition {
	return []TransitionDefinition{{From: "planned", To: "fenced"}, {From: "planned", To: "failed"}, {From: "fenced", To: "restoring"}, {From: "fenced", To: "failed"}, {From: "restoring", To: "verification-required"}, {From: "restoring", To: "failed"}, {From: "restoring", To: "uncertain"}, {From: "verification-required", To: "verified"}, {From: "verification-required", To: "failed"}, {From: "verification-required", To: "uncertain"}}
}

func phase5ScheduledJobTransitions() []TransitionDefinition {
	return []TransitionDefinition{{From: "queued", To: "blocked"}, {From: "queued", To: "skipped"}, {From: "queued", To: "running"}, {From: "queued", To: "cancelled"}, {From: "queued", To: "failed"}, {From: "running", To: "retry-wait"}, {From: "running", To: "succeeded"}, {From: "running", To: "failed"}, {From: "running", To: "uncertain"}, {From: "retry-wait", To: "running"}, {From: "retry-wait", To: "cancelled"}, {From: "retry-wait", To: "failed"}}
}
