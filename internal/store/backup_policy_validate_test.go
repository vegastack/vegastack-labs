package store

import (
	"encoding/hex"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

// These tests exercise the pure cross-field backup-policy validators without a
// database, so they run on every platform (the DB-backed draft tests are
// Linux-tagged with the rest of the store engine).

func validateBackupPtr(value string) *string { return &value }

func validBackupPolicy() generated.BackupPolicy {
	return generated.BackupPolicy{
		Schema: generated.SchemaIDBackupPolicy, SchemaVersion: "1.1.0",
		PolicyID: "policy-a", OwnerID: "owner-a", SourceID: "source-a",
		SourceSelectors: []string{"selector-a"}, ConsistencyHookID: "sqlite-online",
		RepositoryID: validateBackupPtr("repo-a"), RepositoryClass: "standard", ScheduleIntent: "daily",
		ExpectedBytes: 1024, ExpectedGrowthBytes: 512, MinimumFreeBytes: 4096,
		EncryptionKeyReferenceID: validateBackupPtr("enc-a"), RecoveryKeyReferenceID: validateBackupPtr("rec-a"),
		RetentionDays: 7, RestoreTargetID: "restore-a",
		Dependencies: []generated.BackupDependency{{DependencyID: "dep-a", Kind: "binary",
			Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		FunctionalTestRequired: true, RecoveryEpoch: 0, Revision: 1,
	}
}

func validBackupDraftRequest(t *testing.T, policy generated.BackupPolicy) generated.BackupPolicyDraftRequest {
	t.Helper()
	_, sum, err := stateexport.CanonicalJSON(policy)
	if err != nil {
		t.Fatal(err)
	}
	return generated.BackupPolicyDraftRequest{
		Schema: generated.SchemaIDBackupPolicyDraftRequest, SchemaVersion: "1.1.0",
		ExpectedStateRevision: 0, RecoveryEpoch: 0, TargetDigest: "sha256:" + hex.EncodeToString(sum[:]),
		IdempotencyKey: "backup-a", Policy: policy,
	}
}

func TestValidateBackupPolicyClassRules(t *testing.T) {
	if err := validateBackupPolicy(validBackupPolicy(), 0); err != nil {
		t.Fatalf("valid standard policy rejected: %v", err)
	}

	none := validBackupPolicy()
	none.RepositoryClass, none.RepositoryID, none.EncryptionKeyReferenceID, none.RecoveryKeyReferenceID, none.RetentionDays = "none", nil, nil, nil, 0
	if err := validateBackupPolicy(none, 0); err != nil {
		t.Fatalf("valid none policy rejected: %v", err)
	}

	cases := map[string]func(*generated.BackupPolicy){
		"none carrying repository": func(p *generated.BackupPolicy) {
			p.RepositoryClass, p.EncryptionKeyReferenceID, p.RecoveryKeyReferenceID, p.RetentionDays = "none", nil, nil, 0
		},
		"none carrying retention": func(p *generated.BackupPolicy) {
			p.RepositoryClass, p.RepositoryID, p.EncryptionKeyReferenceID, p.RecoveryKeyReferenceID = "none", nil, nil, nil
			p.RetentionDays = 3
		},
		"standard missing repository": func(p *generated.BackupPolicy) { p.RepositoryID = nil },
		"standard missing encryption": func(p *generated.BackupPolicy) { p.EncryptionKeyReferenceID = nil },
		"standard missing recovery":   func(p *generated.BackupPolicy) { p.RecoveryKeyReferenceID = nil },
		"standard zero retention":     func(p *generated.BackupPolicy) { p.RetentionDays = 0 },
		"unknown class":               func(p *generated.BackupPolicy) { p.RepositoryClass = "archive" },
		"duplicate selector":          func(p *generated.BackupPolicy) { p.SourceSelectors = []string{"a", "a"} },
		"empty selectors":             func(p *generated.BackupPolicy) { p.SourceSelectors = nil },
		"duplicate dependency": func(p *generated.BackupPolicy) {
			p.Dependencies = append(p.Dependencies, p.Dependencies[0])
		},
		"epoch mismatch": func(p *generated.BackupPolicy) { p.RecoveryEpoch = 9 },
		"zero revision":  func(p *generated.BackupPolicy) { p.Revision = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			policy := validBackupPolicy()
			mutate(&policy)
			if err := validateBackupPolicy(policy, 0); err == nil {
				t.Fatal("invalid policy accepted")
			} else if Code(err) != generated.ErrorCodeInputInvalid {
				t.Fatalf("unexpected error code %q", Code(err))
			}
		})
	}
}

func TestValidateBackupPolicyDraftRequestCanonicalTargetBinding(t *testing.T) {
	attribution := audit.Attribution{AuthenticatedPrincipalID: "human-a", AuthenticatedPrincipalMethod: "local-os-peer"}
	request := validBackupDraftRequest(t, validBackupPolicy())

	canonical, digest, err := validateBackupPolicyDraftRequest(request, attribution)
	if err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if digest != request.TargetDigest || len(canonical) == 0 {
		t.Fatalf("digest = %q canonical=%d", digest, len(canonical))
	}

	// A target digest that does not match the canonical policy is rejected.
	mismatched := request
	mismatched.TargetDigest = "sha256:" + "b" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, _, err := validateBackupPolicyDraftRequest(mismatched, attribution); err == nil {
		t.Fatal("mismatched target digest accepted")
	}

	// Missing attribution is rejected.
	if _, _, err := validateBackupPolicyDraftRequest(request, audit.Attribution{}); err == nil {
		t.Fatal("missing attribution accepted")
	}
}
