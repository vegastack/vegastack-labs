//go:build linux

package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/backupidentity"
)

func TestBackupCustodyJournalIsWriteAheadAndAppendOnly(t *testing.T) {
	repository := openBackupStore(t)
	digest := seededDraftDigest(t, repository)
	expires := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	if err := repository.AcquireBackupWriterLease(context.Background(), BackupWriterLeaseRequest{
		LeaseID: "lease-custody", JobID: "job-custody", PolicyID: "policy-a", PolicyDigest: digest,
		PlanID: "plan-a", PlanDigest: "sha256:" + strings.Repeat("a", 64), RunID: "run-a", StepID: "step-a",
		RepositoryID: backupidentity.StandardRepository, RepositoryClass: "standard", TargetID: "target-a",
		SourceRevision: 3, RecoveryEpoch: 0, MaximumExpiresAt: expires,
	}); err != nil {
		t.Fatal(err)
	}
	attempt := BackupCustodyAttempt{AttemptID: "custody-a", Role: "writer", PlanID: "plan-a", PlanDigest: "sha256:" + strings.Repeat("a", 64), RunID: "run-a", StepID: "step-a", LeaseID: "lease-custody", RepositoryID: backupidentity.StandardRepository, RepositoryClass: "standard", PointID: "point-a", SourceID: backupidentity.ControlDatabaseSource, SourceRevision: 3, RecoveryEpoch: 0, MaximumExpiresAt: expires, NonceDigest: "sha256:" + strings.Repeat("b", 64)}
	if err := repository.BeginBackupCustody(context.Background(), attempt); err != nil {
		t.Fatal(err)
	}
	if got := countBackupRows(t, repository, "backup_custody_attempts"); got != 1 {
		t.Fatalf("attempt rows=%d", got)
	}
	if got := countBackupRows(t, repository, "backup_custody_outcomes"); got != 0 {
		t.Fatalf("outcome existed before completion: %d", got)
	}
	if err := repository.FinishBackupCustody(context.Background(), attempt.AttemptID, "uncertain"); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.store.conn.ExecContext(context.Background(), `UPDATE backup_custody_attempts SET role='verifier' WHERE attempt_id=?`, attempt.AttemptID); err == nil {
		t.Fatal("custody attempt was mutable")
	}
	if _, err := repository.store.conn.ExecContext(context.Background(), `UPDATE backup_custody_outcomes SET outcome='succeeded' WHERE attempt_id=?`, attempt.AttemptID); err == nil {
		t.Fatal("custody outcome was mutable")
	}
}
