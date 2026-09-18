//go:build linux

package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func seededDraftDigest(t *testing.T, repository *BackupRepository) string {
	t.Helper()
	submission, err := repository.CreateBackupPolicyDraft(context.Background(), backupPolicyDraftFixture(t, backupPolicyFixture()), backupTestAttribution())
	if err != nil {
		t.Fatalf("seed draft: %v", err)
	}
	return submission.PolicyDigest
}

func acquireFixtureLease(t *testing.T, repository *BackupRepository, policyDigest, leaseID, jobID string) {
	t.Helper()
	if err := repository.AcquireBackupWriterLease(context.Background(), BackupWriterLeaseRequest{
		LeaseID: leaseID, JobID: jobID, PolicyID: "policy-a", PolicyDigest: policyDigest,
		PlanID: "plan-a", PlanDigest: "sha256:" + strings.Repeat("a", 64), RunID: "run-a", StepID: "step-a",
		RepositoryID: "repo-a", RepositoryClass: "standard", TargetID: "target-a", RecoveryEpoch: 0,
		MaximumExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("acquire lease %s: %v", leaseID, err)
	}
}

func pendingPointRequest(leaseID, pointID, snapshot string) PendingRecoveryPointRequest {
	return PendingRecoveryPointRequest{
		LeaseID: leaseID, PointID: pointID, SnapshotID: snapshot, SnapshotCount: 1, ObjectCount: 1, ObjectBytes: 4096,
		ContentDigest: "sha256:" + strings.Repeat("c", 64), ManifestDigest: "sha256:" + strings.Repeat("d", 64),
		InventoryDigest: "sha256:" + strings.Repeat("e", 64), SourceRevision: 3, RecoveryEpoch: 0,
		SourceKind: "local", ProofClass: "fixture",
		ExpectedObjects: []ExpectedObjectRow{{Type: "data", Name: strings.Repeat("b", 64), Bytes: 4096, Digest: "sha256:" + strings.Repeat("f", 64)}},
	}
}

func TestBackupWriterLeaseExcludesSecondWriter(t *testing.T) {
	repository := openBackupStore(t)
	digest := seededDraftDigest(t, repository)
	acquireFixtureLease(t, repository, digest, "lease-a", "job-a")
	err := repository.AcquireBackupWriterLease(context.Background(), BackupWriterLeaseRequest{
		LeaseID: "lease-b", JobID: "job-b", PolicyID: "policy-a", PolicyDigest: digest, PlanID: "plan-a",
		PlanDigest: "sha256:" + strings.Repeat("a", 64), RunID: "run-b", StepID: "step-b", RepositoryID: "repo-a",
		RepositoryClass: "standard", TargetID: "target-a", RecoveryEpoch: 0, MaximumExpiresAt: time.Now().Add(time.Hour),
	})
	if Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("second active writer code = %q", Code(err))
	}
}

func TestAppendPendingRecoveryPointIsPendingOnlyAndPreservesPriorPoints(t *testing.T) {
	repository := openBackupStore(t)
	digest := seededDraftDigest(t, repository)

	acquireFixtureLease(t, repository, digest, "lease-a", "job-a")
	pointID, resultDigest, err := repository.AppendPendingRecoveryPoint(context.Background(), pendingPointRequest("lease-a", "point-a", strings.Repeat("1", 64)))
	if err != nil || pointID != "point-a" || !validBackupDigest(resultDigest) {
		t.Fatalf("append pending point = %q %q %v", pointID, resultDigest, err)
	}

	// The point is pending with no verification, and no last-good column exists.
	var status string
	var verifiedAt *string
	if err := repository.store.conn.QueryRowContext(context.Background(), `SELECT verification_status, verified_at FROM recovery_points WHERE point_id=?`, "point-a").Scan(&status, &verifiedAt); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || verifiedAt != nil {
		t.Fatalf("point status=%q verifiedAt=%v (must stay pending, never verified)", status, verifiedAt)
	}
	// The DB refuses to promote a point to verified (that is #117's concern).
	if _, err := repository.store.conn.ExecContext(context.Background(), `UPDATE recovery_points SET verification_status='verified' WHERE point_id=?`, "point-a"); err == nil {
		t.Fatal("recovery point was promotable to verified")
	}

	// The job is pending and the lease is released, so a new writer may proceed.
	var jobStatus string
	if err := repository.store.conn.QueryRowContext(context.Background(), `SELECT status FROM backup_jobs WHERE job_id=?`, "job-a").Scan(&jobStatus); err != nil {
		t.Fatal(err)
	}
	if jobStatus != "pending" {
		t.Fatalf("job status = %q", jobStatus)
	}

	// A second cycle preserves the prior point and adds a new pending one.
	acquireFixtureLease(t, repository, digest, "lease-b", "job-b")
	if _, _, err := repository.AppendPendingRecoveryPoint(context.Background(), pendingPointRequest("lease-b", "point-b", strings.Repeat("2", 64))); err != nil {
		t.Fatalf("second point: %v", err)
	}
	if got := countBackupRows(t, repository, "recovery_points"); got != 2 {
		t.Fatalf("prior point not preserved: %d recovery points", got)
	}
}

func TestVerifyActiveWriterLeaseRejectsReleasedAndExpired(t *testing.T) {
	repository := openBackupStore(t)
	digest := seededDraftDigest(t, repository)
	acquireFixtureLease(t, repository, digest, "lease-a", "job-a")
	if err := repository.VerifyActiveWriterLease(context.Background(), "lease-a", "repo-a", 0, time.Now()); err != nil {
		t.Fatalf("active lease rejected: %v", err)
	}
	// Expired deadline is rejected.
	if err := repository.VerifyActiveWriterLease(context.Background(), "lease-a", "repo-a", 0, time.Now().Add(2*time.Hour)); Code(err) != generated.ErrorCodePlanStale {
		t.Fatalf("expired lease code = %q", Code(err))
	}
	// After the point is appended (lease released) the lease no longer verifies.
	if _, _, err := repository.AppendPendingRecoveryPoint(context.Background(), pendingPointRequest("lease-a", "point-a", strings.Repeat("1", 64))); err != nil {
		t.Fatal(err)
	}
	if err := repository.VerifyActiveWriterLease(context.Background(), "lease-a", "repo-a", 0, time.Now()); Code(err) != generated.ErrorCodePlanStale {
		t.Fatalf("released lease code = %q", Code(err))
	}
}
