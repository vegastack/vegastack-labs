package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func syntheticGateRequest(t *testing.T, command string) []byte {
	t.Helper()
	digest := "sha256:" + strings.Repeat("a", 64)
	var value any
	switch command {
	case generated.CommandNameGateEvidence:
		bundle := generated.GateEvidenceBundle{Schema: generated.SchemaIDGateEvidenceBundle, SchemaVersion: "1.1.0", Facts: []generated.GateEvidenceFact{}, Checks: []generated.GateEvidenceCheck{}, Attachments: []generated.GateEvidenceAttachment{}, CollectorID: "collector-test", ObservedAt: "2026-09-15T00:00:00Z"}
		value = generated.GateEvidenceRequest{Schema: generated.SchemaIDGateEvidenceRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "key-test", EvidenceID: "evidence-test", GateID: "G-008", SubjectID: "site-a", DefinitionVersion: "1.0.0", EvaluatorVersion: "1.0.0", ArtifactDigest: digest, ObservedAt: bundle.ObservedAt, Bundle: bundle}
	case generated.CommandNameGateProfileDraft:
		value = generated.GateProfileDraftRequest{Schema: generated.SchemaIDGateProfileDraftRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "key-test", BindingID: "binding-test", ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "policy-test", PolicyVersion: "1.0.0", Capabilities: []string{}}
	case generated.CommandNameBackupPolicyDraft:
		repo, enc, rec := "repo-a", "enc-a", "rec-a"
		value = generated.BackupPolicyDraftRequest{Schema: generated.SchemaIDBackupPolicyDraftRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "key-test", Policy: generated.BackupPolicy{Schema: generated.SchemaIDBackupPolicy, SchemaVersion: "1.2.0", PolicyID: "policy-a", OwnerID: "owner-a", SourceID: "source-a", SourceSelectors: []string{"selector-a"}, ConsistencyHookID: "sqlite-online", RepositoryID: &repo, RepositoryClass: "standard", ScheduleIntent: "daily", ExpectedBytes: 1024, ExpectedGrowthBytes: 512, MinimumFreeBytes: 4096, EncryptionKeyReferenceID: &enc, RecoveryKeyReferenceID: &rec, RetentionDays: 7, RestoreTargetID: "restore-a", Dependencies: []generated.BackupDependency{{DependencyID: "dep-a", Kind: "binary", Digest: digest}}, FunctionalTestRequired: true, FullPayloadIntervalHours: 24, FunctionalTestIntervalHours: 168, RecoveryEpoch: 2, Revision: 1}}
	case generated.CommandNameBackupRetentionLocksDraft:
		value = generated.BackupRetentionLockDraftRequest{Schema: generated.SchemaIDBackupRetentionLockDraftRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "key-test", Catalog: generated.LocalRetentionLockCatalog{Schema: generated.SchemaIDLocalRetentionLockCatalog, SchemaVersion: "1.0.0", RepositoryID: "repository-standard", RepositoryClass: "standard", SourceCoverageDigest: digest, RecoveryEpoch: 2, Revision: 2, Complete: true, Locks: []generated.BackupRetentionLock{}}}
	case generated.CommandNameBackupRetirementDraft:
		value = generated.BackupRetirementDraftRequest{Schema: generated.SchemaIDBackupRetirementDraftRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "key-test", RepositoryClass: "standard", ReferenceID: "reference-test", ResolverID: "native-systemd", MaterialVersion: "version-test"}
	case generated.CommandNameBackupOffsiteRetirementStage:
		value = generated.BackupOffsiteRetirementStageRequest{Schema: generated.SchemaIDBackupOffsiteRetirementStageRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "key-test", SelectionDigest: digest, PlanID: "plan-a", PlanDigest: digest, OneOwnerProofID: "proof-a", LockAdminReferenceID: "lock-admin", RetentionReferenceID: "retention", CredentialBindingDigest: digest}
	case generated.CommandNameBackupOffsiteRetirementDryRun:
		value = generated.BackupOffsiteRetirementDryRunRequest{Schema: generated.SchemaIDBackupOffsiteRetirementDryRunRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, SelectionDigest: digest, OneOwnerProofID: "proof-a", LockAdminReferenceID: "lock-admin", RetentionReferenceID: "retention"}
	case generated.CommandNameBackupRun:
		value = generated.BackupRunRequest{Schema: generated.SchemaIDBackupRunRequest, SchemaVersion: "1.0.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "key-test", PolicyID: "policy-a", PolicyRevision: 1, PlanID: "plan-a", PlanDigest: digest, HumanAcknowledgementID: "ack-a"}
	case generated.CommandNameBackupVerify:
		value = generated.BackupVerifyRequest{Schema: generated.SchemaIDBackupVerifyRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "key-test", JobID: "job-test", PointID: "point-test", PlanID: "plan-a", PlanDigest: digest, HumanAcknowledgementID: "ack-a"}
	default:
		t.Fatal("unexpected command")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
