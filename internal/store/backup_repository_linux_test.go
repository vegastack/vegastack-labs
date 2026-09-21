//go:build linux

package store

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

func backupPtr(value string) *string { return &value }

func openBackupStore(t *testing.T) *BackupRepository {
	t.Helper()
	return NewBackupRepository(openTestStore(t))
}

func backupPolicyFixture() generated.BackupPolicy {
	return generated.BackupPolicy{
		Schema: generated.SchemaIDBackupPolicy, SchemaVersion: "1.1.0",
		PolicyID: "policy-a", OwnerID: "owner-a", SourceID: backupidentity.ControlDatabaseSource,
		SourceSelectors: []string{backupidentity.ControlDatabaseSelector}, ConsistencyHookID: "sqlite-online",
		RepositoryID: backupPtr(backupidentity.StandardRepository), RepositoryClass: "standard", ScheduleIntent: "daily",
		ExpectedBytes: 1024, ExpectedGrowthBytes: 512, MinimumFreeBytes: 4096,
		EncryptionKeyReferenceID: backupPtr("enc-a"), RecoveryKeyReferenceID: backupPtr("rec-a"),
		RetentionDays: 7, RestoreTargetID: "restore-a",
		Dependencies:           []generated.BackupDependency{{DependencyID: "dep-a", Kind: "binary", Digest: testDigest}},
		FunctionalTestRequired: true, RecoveryEpoch: 0, Revision: 1,
	}
}

func backupPolicyDraftFixture(t *testing.T, policy generated.BackupPolicy) generated.BackupPolicyDraftRequest {
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

func backupTestAttribution() audit.Attribution {
	return audit.Attribution{AuthenticatedPrincipalID: "human-a", AuthenticatedPrincipalMethod: "local-os-peer"}
}

func countBackupRows(t *testing.T, repository *BackupRepository, table string) int {
	t.Helper()
	var count int
	if err := repository.store.Read(context.Background(), func(tx ReadTx) error {
		return tx.queryRow(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&count)
	}); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return count
}

func TestBackupPolicyDraftIsCanonicalInertAndStored(t *testing.T) {
	repository := openBackupStore(t)
	request := backupPolicyDraftFixture(t, backupPolicyFixture())

	submission, err := repository.CreateBackupPolicyDraft(context.Background(), request, backupTestAttribution())
	if err != nil {
		t.Fatalf("create draft: %v", err)
	}
	if submission.PolicyDigest != request.TargetDigest || submission.Status != "draft" || submission.PolicyID != "policy-a" {
		t.Fatalf("submission = %#v", submission)
	}

	// Creating a draft activates nothing: no job, point, lease, or expected object.
	for _, table := range []string{"backup_jobs", "recovery_points", "backup_writer_leases", "backup_expected_objects"} {
		if got := countBackupRows(t, repository, table); got != 0 {
			t.Fatalf("draft creation wrote %d rows to %s", got, table)
		}
	}

	// The stored draft resolves by id and by digest, and its canonical bytes
	// reproduce the bound digest exactly.
	byID, err := repository.GetBackupPolicyDraft(context.Background(), submission.DraftID)
	if err != nil || byID.Digest != submission.PolicyDigest {
		t.Fatalf("get by id = %#v, %v", byID, err)
	}
	byDigest, err := repository.GetBackupPolicyDraftByDigest(context.Background(), submission.PolicyDigest, 0)
	if err != nil || byDigest.DraftID != submission.DraftID || byDigest.RepositoryClass != "standard" {
		t.Fatalf("get by digest = %#v, %v", byDigest, err)
	}

	// The draft catalog is append-only.
	if _, err := repository.store.conn.ExecContext(context.Background(), `UPDATE backup_policy_drafts SET owner_id='x' WHERE draft_id=?`, submission.DraftID); err == nil {
		t.Fatal("append-only update accepted")
	}
	if _, err := repository.store.conn.ExecContext(context.Background(), `DELETE FROM backup_policy_drafts WHERE draft_id=?`, submission.DraftID); err == nil {
		t.Fatal("append-only delete accepted")
	}
}

func TestBackupPolicyDraftEnforcesPolicyClassInvariants(t *testing.T) {
	cases := map[string]func(*generated.BackupPolicy){
		"none with retention": func(p *generated.BackupPolicy) {
			p.RepositoryClass, p.RepositoryID, p.EncryptionKeyReferenceID, p.RecoveryKeyReferenceID = "none", nil, nil, nil
			p.RetentionDays = 7
		},
		"none with repository": func(p *generated.BackupPolicy) {
			p.RepositoryClass, p.EncryptionKeyReferenceID, p.RecoveryKeyReferenceID, p.RetentionDays = "none", nil, nil, 0
		},
		"standard without repository": func(p *generated.BackupPolicy) { p.RepositoryID = nil },
		"standard without keys":       func(p *generated.BackupPolicy) { p.EncryptionKeyReferenceID = nil },
		"standard zero retention":     func(p *generated.BackupPolicy) { p.RetentionDays = 0 },
		"unregistered source":         func(p *generated.BackupPolicy) { p.SourceID = "source-a" },
		"unregistered selector":       func(p *generated.BackupPolicy) { p.SourceSelectors = []string{"selector-a"} },
		"unregistered repository":     func(p *generated.BackupPolicy) { p.RepositoryID = backupPtr("repo-a") },
		"duplicate selector":          func(p *generated.BackupPolicy) { p.SourceSelectors = []string{"selector-a", "selector-a"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			repository := openBackupStore(t)
			policy := backupPolicyFixture()
			mutate(&policy)
			request := backupPolicyDraftFixture(t, policy)
			if _, err := repository.CreateBackupPolicyDraft(context.Background(), request, backupTestAttribution()); err == nil {
				t.Fatal("invalid policy accepted")
			} else if Code(err) != generated.ErrorCodeInputInvalid {
				t.Fatalf("unexpected error code %q", Code(err))
			}
		})
	}
}

func TestBackupPolicyDraftIsIdempotentAndRejectsConflict(t *testing.T) {
	repository := openBackupStore(t)
	request := backupPolicyDraftFixture(t, backupPolicyFixture())

	first, err := repository.CreateBackupPolicyDraft(context.Background(), request, backupTestAttribution())
	if err != nil {
		t.Fatal(err)
	}
	second, err := repository.CreateBackupPolicyDraft(context.Background(), request, backupTestAttribution())
	if err != nil || second != first {
		t.Fatalf("retry changed authority: %#v %v", second, err)
	}

	// Same idempotency key, different canonical policy => conflict.
	conflicting := backupPolicyFixture()
	conflicting.ExpectedBytes = 2048
	conflictingRequest := backupPolicyDraftFixture(t, conflicting)
	conflictingRequest.IdempotencyKey = request.IdempotencyKey
	if _, err := repository.CreateBackupPolicyDraft(context.Background(), conflictingRequest, backupTestAttribution()); err == nil {
		t.Fatal("idempotency-key reuse with new policy accepted")
	} else if Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("unexpected error code %q", Code(err))
	}
}
