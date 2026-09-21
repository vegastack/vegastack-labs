//go:build linux

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/backupidentity"
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
		RepositoryID: backupidentity.StandardRepository, RepositoryClass: "standard", TargetID: "target-a", RecoveryEpoch: 0,
		SourceRevision:   3,
		MaximumExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("acquire lease %s: %v", leaseID, err)
	}
}

func pendingPointRequest(leaseID, pointID, snapshot, policyDigest string) PendingRecoveryPointRequest {
	objects := []ExpectedObjectRow{
		{Type: "data", Name: strings.Repeat("b", 64), Bytes: 4096, Digest: "sha256:" + strings.Repeat("f", 64)},
		{Type: "config", Name: "config", Bytes: 512, Digest: "sha256:" + strings.Repeat("a", 64)},
		{Type: "keys", Name: strings.Repeat("c", 64), Bytes: 256, Digest: "sha256:" + strings.Repeat("b", 64)},
		{Type: "snapshots", Name: snapshot, Bytes: 1024, Digest: "sha256:" + strings.Repeat("c", 64)},
	}
	objectBytes := int64(4096 + 512 + 256 + 1024)
	inventoryDigest := pendingInventoryDigest(objects)
	dependencies := []ExpectedDependencyRow{{DependencyID: "dep-a", Kind: "binary", Digest: testDigest}}
	manifest, _ := json.Marshal(pendingCreationManifest{
		Schema: "vegastack-labs.dev/backup-creation-manifest", SchemaVersion: "1.1.0",
		PolicyID: "policy-a", PolicyDigest: policyDigest,
		PointID: pointID, RunID: "run-a", StepID: "step-a", RepositoryID: backupidentity.StandardRepository, RepositoryClass: "standard",
		SourceID: backupidentity.ControlDatabaseSource, SourceSelectors: []string{backupidentity.ControlDatabaseSelector},
		SourceRevision: 3, RecoveryEpoch: 0, ConsistencyHookID: "sqlite-online", ConsistencySuccess: true,
		SnapshotID: snapshot, SnapshotCount: 1, ExpectedObjectCount: int64(len(objects)), ExpectedObjectBytes: objectBytes,
		InventoryDigest: inventoryDigest, ExpectedObjects: objects,
		DependencyInventoryDigest: pendingDependencyInventoryDigest(dependencies), ExpectedDependencies: dependencies,
		KeyReferenceID: "enc-a",
		ResticDigest:   "sha256:" + strings.Repeat("1", 64), PlatformDigest: "sha256:" + strings.Repeat("2", 64),
		StartedAt: "2026-09-21T00:00:00Z", CompletedAt: "2026-09-21T00:00:01Z",
	})
	sum := sha256.Sum256(manifest)
	return PendingRecoveryPointRequest{
		LeaseID: leaseID, PointID: pointID, SnapshotID: snapshot, SnapshotCount: 1, ObjectCount: int64(len(objects)), ObjectBytes: objectBytes,
		ContentDigest: "sha256:" + strings.Repeat("c", 64), ManifestDigest: "sha256:" + hex.EncodeToString(sum[:]), ManifestJSON: manifest,
		InventoryDigest: inventoryDigest, SourceRevision: 3, RecoveryEpoch: 0,
		SourceKind: "local", ProofClass: "fixture",
		ExpectedObjects: objects,
	}
}

func TestBackupWriterLeaseExcludesSecondWriter(t *testing.T) {
	repository := openBackupStore(t)
	digest := seededDraftDigest(t, repository)
	acquireFixtureLease(t, repository, digest, "lease-a", "job-a")
	err := repository.AcquireBackupWriterLease(context.Background(), BackupWriterLeaseRequest{
		LeaseID: "lease-b", JobID: "job-b", PolicyID: "policy-a", PolicyDigest: digest, PlanID: "plan-a",
		PlanDigest: "sha256:" + strings.Repeat("a", 64), RunID: "run-b", StepID: "step-b", RepositoryID: backupidentity.StandardRepository,
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
	pointID, resultDigest, err := repository.AppendPendingRecoveryPoint(context.Background(), pendingPointRequest("lease-a", "point-a", strings.Repeat("1", 64), digest))
	if err != nil || pointID != "point-a" || !validBackupDigest(resultDigest) {
		t.Fatalf("append pending point = %q %q %v", pointID, resultDigest, err)
	}
	readback, err := repository.GetPendingRecoveryPoint(context.Background(), pointID)
	if err != nil || readback.PointID != pointID || readback.ManifestDigest != resultDigest || len(readback.ExpectedObjects) != 4 {
		t.Fatalf("typed pending receipt readback = %#v, %v", readback, err)
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
	if _, _, err := repository.AppendPendingRecoveryPoint(context.Background(), pendingPointRequest("lease-b", "point-b", strings.Repeat("2", 64), digest)); err != nil {
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
	if err := repository.VerifyActiveWriterLease(context.Background(), "lease-a", backupidentity.StandardRepository, 0, time.Now()); err != nil {
		t.Fatalf("active lease rejected: %v", err)
	}
	// Expired deadline is rejected.
	if err := repository.VerifyActiveWriterLease(context.Background(), "lease-a", backupidentity.StandardRepository, 0, time.Now().Add(2*time.Hour)); Code(err) != generated.ErrorCodePlanStale {
		t.Fatalf("expired lease code = %q", Code(err))
	}
	// After the point is appended (lease released) the lease no longer verifies.
	if _, _, err := repository.AppendPendingRecoveryPoint(context.Background(), pendingPointRequest("lease-a", "point-a", strings.Repeat("1", 64), digest)); err != nil {
		t.Fatal(err)
	}
	if err := repository.VerifyActiveWriterLease(context.Background(), "lease-a", backupidentity.StandardRepository, 0, time.Now()); Code(err) != generated.ErrorCodePlanStale {
		t.Fatalf("released lease code = %q", Code(err))
	}
}

func TestAppendPendingRecoveryPointRejectsNonLocalFixtureProvenance(t *testing.T) {
	for _, mutate := range []func(*PendingRecoveryPointRequest){
		func(r *PendingRecoveryPointRequest) { r.SourceKind = "independent" },
		func(r *PendingRecoveryPointRequest) { r.ProofClass = "live" },
	} {
		repository := openBackupStore(t)
		digest := seededDraftDigest(t, repository)
		acquireFixtureLease(t, repository, digest, "lease-a", "job-a")
		request := pendingPointRequest("lease-a", "point-a", strings.Repeat("1", 64), digest)
		mutate(&request)
		if _, _, err := repository.AppendPendingRecoveryPoint(context.Background(), request); Code(err) != generated.ErrorCodeInputInvalid {
			t.Fatalf("non-local/fixture provenance accepted (code=%q)", Code(err))
		}
	}
}

func TestAppendPendingRecoveryPointRejectsForgedManifestInventoryAndLease(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*PendingRecoveryPointRequest, *pendingCreationManifest)
	}{
		{"inventory digest", func(request *PendingRecoveryPointRequest, manifest *pendingCreationManifest) {
			request.InventoryDigest = "sha256:" + strings.Repeat("e", 64)
			manifest.InventoryDigest = request.InventoryDigest
		}},
		{"object name", func(request *PendingRecoveryPointRequest, manifest *pendingCreationManifest) {
			request.ExpectedObjects[0].Name = "not-hex"
			manifest.ExpectedObjects[0].Name = "not-hex"
			request.InventoryDigest = pendingInventoryDigest(request.ExpectedObjects)
			manifest.InventoryDigest = request.InventoryDigest
		}},
		{"source revision", func(request *PendingRecoveryPointRequest, manifest *pendingCreationManifest) {
			request.SourceRevision++
			manifest.SourceRevision = request.SourceRevision
		}},
		{"policy binding", func(_ *PendingRecoveryPointRequest, manifest *pendingCreationManifest) {
			manifest.PolicyDigest = "sha256:" + strings.Repeat("0", 64)
		}},
		{"run binding", func(_ *PendingRecoveryPointRequest, manifest *pendingCreationManifest) {
			manifest.RunID = "different-run"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := openBackupStore(t)
			policyDigest := seededDraftDigest(t, repository)
			acquireFixtureLease(t, repository, policyDigest, "lease-a", "job-a")
			request := pendingPointRequest("lease-a", "point-a", strings.Repeat("1", 64), policyDigest)
			var manifest pendingCreationManifest
			if err := json.Unmarshal(request.ManifestJSON, &manifest); err != nil {
				t.Fatal(err)
			}
			test.mutate(&request, &manifest)
			body, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			request.ManifestJSON = body
			sum := sha256.Sum256(body)
			request.ManifestDigest = "sha256:" + hex.EncodeToString(sum[:])
			if _, _, err := repository.AppendPendingRecoveryPoint(context.Background(), request); err == nil {
				t.Fatal("forged pending point was published")
			}
			if got := countBackupRows(t, repository, "recovery_points"); got != 0 {
				t.Fatalf("forged point persisted: %d", got)
			}
		})
	}
}
