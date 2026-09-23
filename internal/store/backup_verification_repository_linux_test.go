//go:build linux

package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func seededVerificationPoint(t *testing.T) (*BackupRepository, PendingRecoveryPoint, RevisionToken) {
	t.Helper()
	repository := openBackupStore(t)
	digest := seededDraftDigest(t, repository)
	acquireFixtureLease(t, repository, digest, "writer-a", "job-a")
	if _, _, err := repository.AppendPendingRecoveryPoint(context.Background(), pendingPointRequest("writer-a", "point-a", strings.Repeat("1", 64), digest)); err != nil {
		t.Fatal(err)
	}
	point, err := repository.GetPendingRecoveryPoint(context.Background(), "point-a")
	if err != nil {
		t.Fatal(err)
	}
	current, err := NewPlanRepository(repository.store).CurrentRevision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return repository, point, current
}

func verificationRequest(t *testing.T, point PendingRecoveryPoint, revision RevisionToken, proofClass, result string) LocalVerificationRequest {
	t.Helper()
	var manifest pendingCreationManifest
	if err := json.Unmarshal(point.ManifestJSON, &manifest); err != nil {
		t.Fatal(err)
	}
	return LocalVerificationRequest{VerificationID: "verify-" + proofClass + "-" + result, RunID: "run-verify", PointID: point.PointID, ReadLeaseID: "reader-a",
		ManifestDigest: point.ManifestDigest, InventoryDigest: point.InventoryDigest, ObservedDigest: point.InventoryDigest,
		ContentDigest: point.ContentDigest, CatalogDigest: manifest.CatalogDigest, DependencyDigest: manifest.DependencyInventoryDigest,
		KeyReferenceID: manifest.KeyReferenceID, SourceRevision: point.SourceRevision, Expected: revision,
		ProofClass: proofClass, Result: result, ReasonCode: "fixture-check", FullReadAt: time.Now().Add(-2 * time.Minute), FunctionalRestoredAt: time.Now().Add(-time.Minute)}
}

func TestLocalLastGoodSurvivesFailedFixtureAndStaleProof(t *testing.T) {
	ctx := context.Background()
	repository, point, revision := seededVerificationPoint(t)
	lease := BackupReadLeaseRequest{LeaseID: "reader-a", PointID: point.PointID, RepositoryID: backupidentity.StandardRepository,
		RepositoryClass: "standard", SourceRevision: point.SourceRevision, Expected: revision, MaximumExpiresAt: time.Now().Add(time.Hour)}
	if err := repository.AcquireBackupReadLease(ctx, lease); err != nil {
		t.Fatal(err)
	}
	if err := repository.VerifyActiveReadLease(ctx, lease, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := repository.AcquireBackupWriterLease(ctx, BackupWriterLeaseRequest{LeaseID: "writer-b", JobID: "job-b", PolicyID: "policy-a", PolicyDigest: seededDraftDigest(t, repository), PlanID: "plan-a", PlanDigest: "sha256:" + strings.Repeat("a", 64), RunID: "run-b", StepID: "step-b", RepositoryID: backupidentity.StandardRepository, RepositoryClass: "standard", TargetID: "target-a", RecoveryEpoch: revision.RecoveryEpoch, MaximumExpiresAt: time.Now().Add(time.Hour)}); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("writer during read lease: %v", err)
	}
	failed := verificationRequest(t, point, revision, "fixture", "failed")
	failed.FullReadAt, failed.FunctionalRestoredAt = time.Time{}, time.Time{}
	failedReceipt, err := repository.AppendLocalVerification(ctx, failed)
	if err != nil || failedReceipt.Status != "failed" {
		t.Fatalf("failed proof: %#v %v", failedReceipt, err)
	}
	if err := repository.AdvanceLocalLastGood(ctx, failedReceipt, revision, ""); err == nil {
		t.Fatal("failed proof advanced last-good")
	}
	fixture := verificationRequest(t, point, revision, "fixture", "passed")
	fixtureReceipt, err := repository.AppendLocalVerification(ctx, fixture)
	if err != nil || fixtureReceipt.Status != "fixture-only" {
		t.Fatalf("fixture proof: %#v %v", fixtureReceipt, err)
	}
	readback, err := repository.GetLocalVerificationByDigest(ctx, fixtureReceipt.ProofDigest)
	if err != nil || readback.VerificationID != fixtureReceipt.VerificationID || readback.ProofDigest != fixtureReceipt.ProofDigest {
		t.Fatalf("exact immutable proof readback=%#v err=%v", readback, err)
	}
	if _, err := repository.GetLocalVerificationByDigest(ctx, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("unknown proof digest resolved to an older point attempt")
	}
	if err := repository.AdvanceLocalLastGood(ctx, fixtureReceipt, revision, ""); err == nil {
		t.Fatal("fixture proof advanced last-good")
	}
	status, err := repository.ReadLocalBackupStatus(ctx)
	if err != nil || len(status.LastGood) != 0 || status.Jobs[0].Status != "pending" || status.Verifications[0].Status != "fixture-only" {
		t.Fatalf("fixture backup status=%#v err=%v", status, err)
	}
	if _, err := repository.ReadLocalBackupStatusScoped(ctx, authorization.ReadScope{PrincipalID: "fake", Capability: "backup.read", ResourceKind: "backup", GrantRevision: 1, ScopeDigest: "fake"}); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("forged backup read scope admitted: %v", err)
	}
	seedReadGrant(t, repository.store, "backup-reader", "backup.read", "backup", "point-a", 1, "active")
	reader := NewReadAuthorizer(repository.store)
	pointScope, err := reader.AuthorizeRead(ctx, identity.Principal{ID: "backup-reader", Method: identity.LocalOSPeerMethod}, authorization.ReadTarget{Capability: "backup.read", ResourceKind: "backup", ResourceID: "point-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ReadLocalBackupStatusScoped(ctx, pointScope); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("point-only grant read global status: %v", err)
	}
	seedReadGrant(t, repository.store, "backup-global-reader", "backup.read", "backup", "current", 1, "active")
	globalScope, err := reader.AuthorizeRead(ctx, identity.Principal{ID: "backup-global-reader", Method: identity.LocalOSPeerMethod}, authorization.ReadTarget{Capability: "backup.read", ResourceKind: "backup", ResourceID: "current"})
	if err != nil {
		t.Fatal(err)
	}
	if scoped, err := repository.ReadLocalBackupStatusScoped(ctx, globalScope); err != nil || len(scoped.Jobs) != 1 || scoped.Jobs[0].JobID != point.JobID {
		t.Fatalf("global backup status=%#v err=%v", scoped, err)
	}
	stale := verificationRequest(t, point, revision, "live", "passed")
	stale.Expected.RecoveryEpoch++
	if _, err := repository.AppendLocalVerification(ctx, stale); Code(err) != generated.ErrorCodePlanStale {
		t.Fatalf("stale epoch: %v", err)
	}
	var count int
	if err := repository.store.conn.QueryRowContext(ctx, `SELECT COUNT(1) FROM backup_local_last_good`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("last-good count=%d err=%v", count, err)
	}
}

func TestLocalLastGoodCurrentLiveProofAdvancesOnce(t *testing.T) {
	ctx := context.Background()
	repository, point, revision := seededVerificationPoint(t)
	lease := BackupReadLeaseRequest{LeaseID: "reader-a", PointID: point.PointID, RepositoryID: backupidentity.StandardRepository,
		RepositoryClass: "standard", SourceRevision: point.SourceRevision, Expected: revision, MaximumExpiresAt: time.Now().Add(time.Hour)}
	if err := repository.AcquireBackupReadLease(ctx, lease); err != nil {
		t.Fatal(err)
	}
	request := verificationRequest(t, point, revision, "live", "passed")
	receipt, err := repository.AppendLocalVerification(ctx, request)
	if err != nil || receipt.Status != "local-verified" {
		t.Fatalf("live proof: %#v %v", receipt, err)
	}
	if err := repository.AdvanceLocalLastGood(ctx, receipt, revision, ""); err != nil {
		t.Fatal(err)
	}
	status, err := repository.ReadLocalBackupStatus(ctx)
	if err != nil || len(status.Policies) != 1 || len(status.Jobs) != 1 || len(status.Verifications) != 1 || len(status.LastGood) != 1 ||
		status.Jobs[0].Status != "verified" || status.Verifications[0].Status != "local-verified" ||
		status.Verifications[0].FullPayloadDueAt == nil || status.Verifications[0].FunctionalTestDueAt == nil {
		t.Fatalf("live backup status=%#v err=%v", status, err)
	}
	repository.store.config.Clock = func() time.Time { return time.Now().Add(25 * time.Hour) }
	overdue, err := repository.ReadLocalBackupStatus(ctx)
	if err != nil || overdue.Verifications[0].Status != "full-payload-due" || overdue.Jobs[0].Status == "verified" || len(overdue.LastGood) != 1 {
		t.Fatalf("overdue backup status=%#v err=%v", overdue, err)
	}
	repository.store.config.Clock = time.Now
	if err := repository.AdvanceLocalLastGood(ctx, receipt, revision, ""); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("second advance: %v", err)
	}
	var last string
	if err := repository.store.conn.QueryRowContext(ctx, `SELECT verification_id FROM backup_local_last_good WHERE repository_class='standard'`).Scan(&last); err != nil || last != receipt.VerificationID {
		t.Fatalf("last-good=%q err=%v", last, err)
	}
}

func TestOverdueFullReadCannotAdvanceLastGood(t *testing.T) {
	ctx := context.Background()
	repository, point, revision := seededVerificationPoint(t)
	lease := BackupReadLeaseRequest{LeaseID: "reader-a", PointID: point.PointID, RepositoryID: backupidentity.StandardRepository,
		RepositoryClass: "standard", SourceRevision: point.SourceRevision, Expected: revision, MaximumExpiresAt: time.Now().Add(time.Hour)}
	if err := repository.AcquireBackupReadLease(ctx, lease); err != nil {
		t.Fatal(err)
	}
	request := verificationRequest(t, point, revision, "live", "passed")
	request.FullReadAt = time.Now().Add(-25 * time.Hour)
	receipt, err := repository.AppendLocalVerification(ctx, request)
	if err != nil || receipt.Status != "full-payload-due" {
		t.Fatalf("overdue proof=%#v err=%v", receipt, err)
	}
	if err := repository.AdvanceLocalLastGood(ctx, receipt, revision, ""); err == nil {
		t.Fatal("overdue full-read advanced last-good")
	}
	status, err := repository.ReadLocalBackupStatus(ctx)
	if err != nil || status.Verifications[0].Status != "full-payload-due" || status.Jobs[0].Status == "verified" || len(status.LastGood) != 0 {
		t.Fatalf("overdue backup status=%#v err=%v", status, err)
	}
}
