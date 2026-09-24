package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

type databaseExportStub struct{ calls int }

func (stub *databaseExportStub) Draft(context.Context, generated.DatabaseExportRequest, change.AuthorScope) (generated.DatabaseExportDraftSubmission, bool, error) {
	stub.calls++
	return generated.DatabaseExportDraftSubmission{}, true, nil
}

func TestDatabaseRoutesAuthorizeFixedResourceBeforeBodyRead(t *testing.T) {
	denied := &effectiveAuthorizationStub{decision: authorization.Decision{ReasonCode: authorization.ReasonGrantMissing}}
	runs := &runAPIStub{plan: apiRunPlan()}
	app := newRunTestApplicationWithAuthorization(t, runs, denied)
	exports := &databaseExportStub{}
	backupConfig := BackupOperations{Drafts: &backupDraftServiceStub{}, Status: backupStatusStub{}, Runs: RunOperationConfig{Runs: runs, Plans: runs, Acknowledgements: runs, Results: app.config.Results, Authorization: app.effective}, Results: app.config.Results}
	if err := RegisterDatabaseOperations(app, DatabaseOperations{Backups: backupConfig, Restores: RestoreConfig{Operations: &restoreOperationsStub{}, Results: app.config.Results}, Exports: exports, Results: app.config.Results}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/database/backups", "/api/v1/database/verifications", "/api/v1/database/restores", "/api/v1/database/exports"} {
		body := &countingBody{data: bytes.NewReader([]byte(`{"privateCanary":"must-not-read"}`))}
		request := httptest.NewRequest(http.MethodPost, path, nil)
		request.Body = body
		request.Header.Set("Content-Type", "application/json")
		request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}))
		response := httptest.NewRecorder()
		app.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden || body.reads != 0 || strings.Contains(response.Body.String(), "privateCanary") {
			t.Fatalf("path=%s status=%d reads=%d body=%s", path, response.Code, body.reads, response.Body.String())
		}
		record := denied.records[len(denied.records)-1]
		if record.Decision.Target.ResourceKind != "database" || record.Decision.Target.ResourceID != "database" {
			t.Fatalf("path=%s target=%#v", path, record.Decision.Target)
		}
	}
	if runs.submitCalls != 0 || exports.calls != 0 {
		t.Fatalf("submits=%d exports=%d", runs.submitCalls, exports.calls)
	}
}

func TestDatabaseVerifyReusesExactApprovedPointEffect(t *testing.T) {
	plan := apiRunPlan()
	plan.Operations[0].OperationType, plan.Operations[0].AdapterID, plan.Operations[0].TargetID = "backup.local.verify", "local.backup", "point-test"
	runs := &runAPIStub{plan: plan, run: apiRunResult(plan)}
	app := newRunTestApplication(t, runs)
	point := "point-test"
	status := backupStatusStub{data: generated.BackupStatusData{Schema: generated.SchemaIDBackupStatusData, SchemaVersion: "1.3.0", Policies: []generated.BackupPolicy{}, Jobs: []generated.BackupJob{{Schema: generated.SchemaIDBackupJob, SchemaVersion: "1.1.0", JobID: "job-test", PolicyID: "policy-test", SourceKind: "fixture", ProofClass: "fixture", PointID: &point, Status: "pending", RecoveryEpoch: plan.Binding.RecoveryEpoch}}, Verifications: []generated.BackupVerificationAttempt{}, LastGood: []generated.BackupLastGood{}, Retirements: []generated.BackupLocalRetirementStatus{}, Offsite: []generated.BackupOffsiteStatus{}, RecoveryEpoch: plan.Binding.RecoveryEpoch}}
	backupConfig := BackupOperations{Drafts: &backupDraftServiceStub{}, Status: status, Runs: RunOperationConfig{Runs: runs, Plans: runs, Acknowledgements: runs, Results: app.config.Results, Authorization: app.effective}, Results: app.config.Results}
	if err := RegisterDatabaseOperations(app, DatabaseOperations{Backups: backupConfig, Restores: RestoreConfig{Operations: &restoreOperationsStub{}, Results: app.config.Results}, Exports: &databaseExportStub{}, Results: app.config.Results}); err != nil {
		t.Fatal(err)
	}
	input := generated.BackupVerifyRequest{Schema: generated.SchemaIDBackupVerifyRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, TargetDigest: plan.Operations[0].InputDigest, IdempotencyKey: "database-verify-test", JobID: "job-test", PointID: point, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, HumanAcknowledgementID: "ack-test"}
	body, _ := json.Marshal(input)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/database/verifications", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-run-test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusOK || runs.submitCalls != 1 {
		t.Fatalf("status=%d submits=%d body=%s", response.Code, runs.submitCalls, response.Body.String())
	}
}
