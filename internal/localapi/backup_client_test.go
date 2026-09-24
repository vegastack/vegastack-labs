package localapi

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestBackupClientUsesResourceAddressedMutationRoutes(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	run := generated.BackupRunRequest{Schema: generated.SchemaIDBackupRunRequest, SchemaVersion: "1.0.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "key-run", PolicyID: "policy-a", PolicyRevision: 1, PlanID: "plan-a", PlanDigest: digest, HumanAcknowledgementID: "ack-a"}
	job := generated.BackupJob{Schema: generated.SchemaIDBackupJob, SchemaVersion: "1.1.0", JobID: "job-a", PolicyID: run.PolicyID, SourceKind: "local", ProofClass: "live", Status: "pending", RecoveryEpoch: 2}
	raw, profile, captured := serveFixedResponse(t, http.StatusOK, operationEnvelope(t, "api.v1.backup-jobs.create", true, 2, 8, job))
	response, err := NewClient(clientTestFactory()).RunBackup(context.Background(), profile, run)
	request := <-captured
	if err != nil || !bytes.Equal(response.Raw, raw) || request.method != http.MethodPost || request.path != "/api/v1/backup-policies/policy-a/jobs" || !bytes.Contains(request.body, []byte(`"policyId":"policy-a"`)) {
		t.Fatalf("run response/request = %#v/%#v err=%v", response, request, err)
	}

	point := "point-a"
	verify := generated.BackupVerifyRequest{Schema: generated.SchemaIDBackupVerifyRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 8, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "key-verify", JobID: "job-a", PointID: point, PlanID: "plan-b", PlanDigest: digest, HumanAcknowledgementID: "ack-b"}
	job.PointID, job.Status, job.VerificationDigest = &point, "verified", &digest
	raw, profile, captured = serveFixedResponse(t, http.StatusOK, operationEnvelope(t, "api.v1.backup-verifications.create", true, 2, 9, job))
	response, err = NewClient(clientTestFactory()).VerifyBackup(context.Background(), profile, verify)
	request = <-captured
	if err != nil || !bytes.Equal(response.Raw, raw) || request.method != http.MethodPost || request.path != "/api/v1/recovery-points/point-a/verifications" || !bytes.Contains(request.body, []byte(`"pointId":"point-a"`)) {
		t.Fatalf("verify response/request = %#v/%#v err=%v", response, request, err)
	}
}

func TestBackupStatusAcceptsOnlySanitizedProjection(t *testing.T) {
	status := generated.BrowserBackupStatusData{Schema: generated.SchemaIDBrowserBackupStatusData, SchemaVersion: "1.0.0", Status: "healthy", ReasonCode: "verified-recovery-point", SourceKind: "local", ProofClass: "live", RecoveryRequired: false, StateRevision: 7, RecoveryEpoch: 2, SafeNextAction: "none"}
	raw, profile, captured := serveFixedResponse(t, http.StatusOK, operationEnvelope(t, "api.v1.backups.status", false, 2, 7, status))
	response, err := NewClient(clientTestFactory()).BackupStatus(context.Background(), profile)
	request := <-captured
	if err != nil || !bytes.Equal(response.Raw, raw) || request.method != http.MethodGet || request.path != "/api/v1/backups/status" || len(request.body) != 0 || response.Data.Status != status.Status || response.Data.SafeNextAction != status.SafeNextAction || response.Data.StateRevision != status.StateRevision {
		t.Fatalf("status response/request = %#v/%#v err=%v", response, request, err)
	}

	private := generated.BackupStatusData{Schema: generated.SchemaIDBackupStatusData, SchemaVersion: "1.3.0", Policies: []generated.BackupPolicy{}, Jobs: []generated.BackupJob{}, Verifications: []generated.BackupVerificationAttempt{}, LastGood: []generated.BackupLastGood{}, Retirements: []generated.BackupLocalRetirementStatus{}, Offsite: []generated.BackupOffsiteStatus{}, RecoveryEpoch: 2}
	_, profile, captured = serveFixedResponse(t, http.StatusOK, operationEnvelope(t, "api.v1.backups.status", false, 2, 7, private))
	if _, err := NewClient(clientTestFactory()).BackupStatus(context.Background(), profile); err == nil {
		t.Fatal("obsolete private backup status passed browser-contract validation")
	}
	<-captured
}
