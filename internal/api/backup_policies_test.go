package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
)

type backupDraftServiceStub struct {
	calls      int
	submission generated.BackupPolicyDraftSubmission
	err        error
}

type backupStatusStub struct{ data generated.BackupStatusData }

func (stub backupStatusStub) ReadLocalBackupStatus(context.Context) (generated.BackupStatusData, error) {
	return stub.data, nil
}

func (stub *backupDraftServiceStub) CreateBackupPolicyDraft(_ context.Context, _ generated.BackupPolicyDraftRequest, _ audit.Attribution) (generated.BackupPolicyDraftSubmission, error) {
	stub.calls++
	return stub.submission, stub.err
}

func backupTestApp(t *testing.T, service *backupDraftServiceStub) *Application {
	t.Helper()
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "0.0.0-test", ReleaseBuildID: "build-test"}, func() (string, error) { return "request-backup-test", nil })
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: allowOperationAuthorizer(), Reads: testReads{}, Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	effective := &effectiveAuthorizationStub{}
	app.effective = EffectiveAuthorizationConfig{Authorizer: effective, Recorder: effective, Clock: time.Now}
	if err := RegisterBackupOperations(app, BackupOperations{Drafts: service, Results: factory}); err != nil {
		t.Fatal(err)
	}
	return app
}

func backupDraftRequestJSON(t *testing.T) []byte {
	t.Helper()
	repo, enc, rec := "repo-a", "enc-a", "rec-a"
	digest := "sha256:" + strings.Repeat("a", 64)
	request := generated.BackupPolicyDraftRequest{
		Schema: generated.SchemaIDBackupPolicyDraftRequest, SchemaVersion: "1.1.0",
		ExpectedStateRevision: 0, RecoveryEpoch: 0, TargetDigest: digest, IdempotencyKey: "backup-a",
		Policy: generated.BackupPolicy{
			Schema: generated.SchemaIDBackupPolicy, SchemaVersion: "1.2.0",
			PolicyID: "policy-a", OwnerID: "owner-a", SourceID: "source-a",
			SourceSelectors: []string{"selector-a"}, ConsistencyHookID: "sqlite-online",
			RepositoryID: &repo, RepositoryClass: "standard", ScheduleIntent: "daily",
			ExpectedBytes: 1024, ExpectedGrowthBytes: 512, MinimumFreeBytes: 4096,
			EncryptionKeyReferenceID: &enc, RecoveryKeyReferenceID: &rec,
			RetentionDays: 7, RestoreTargetID: "restore-a",
			Dependencies:           []generated.BackupDependency{{DependencyID: "dep-a", Kind: "binary", Digest: digest}},
			FunctionalTestRequired: true, FullPayloadIntervalHours: 24, FunctionalTestIntervalHours: 168, RecoveryEpoch: 0, Revision: 1,
		},
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBackupPolicyDraftEndpointStoresAndReturnsSubmission(t *testing.T) {
	service := &backupDraftServiceStub{submission: generated.BackupPolicyDraftSubmission{
		Schema: generated.SchemaIDBackupPolicyDraftSubmission, SchemaVersion: "1.1.0",
		DraftID: "backup-draft-x", PolicyID: "policy-a", PolicyDigest: "sha256:" + strings.Repeat("a", 64),
		Status: "draft", StateRevision: 1, RecoveryEpoch: 0,
	}}
	app := backupTestApp(t, service)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/backups/policies/drafts", strings.NewReader(string(backupDraftRequestJSON(t))))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)

	if response.Code != http.StatusOK || service.calls != 1 || !strings.Contains(response.Body.String(), "backup-draft-x") {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, service.calls, response.Body.String())
	}
}

func TestBackupPolicyDraftEndpointDoesNotActivateBackupRun(t *testing.T) {
	app := backupTestApp(t, &backupDraftServiceStub{})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/backups/run", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("backup run status = %d (expected 404; the run route must stay planned/#117)", response.Code)
	}
}

func TestBackupVerifyRouteRequiresExactPointPlanAndHumanAcknowledgement(t *testing.T) {
	plan := apiRunPlan()
	plan.Operations[0].OperationType = "backup.local.verify"
	plan.Operations[0].AdapterID = "local.backup"
	plan.Operations[0].TargetID = "point-test"
	runs := &runAPIStub{plan: plan, run: apiRunResult(plan)}
	app := newRunTestApplication(t, runs)
	point := "point-test"
	status := backupStatusStub{data: generated.BackupStatusData{Schema: generated.SchemaIDBackupStatusData, SchemaVersion: "1.1.0", Policies: []generated.BackupPolicy{}, Jobs: []generated.BackupJob{{Schema: generated.SchemaIDBackupJob, SchemaVersion: "1.1.0", JobID: "job-test", PolicyID: "policy-test", SourceKind: "fixture", ProofClass: "fixture", PointID: &point, Status: "pending", RecoveryEpoch: plan.Binding.RecoveryEpoch}}, Verifications: []generated.BackupVerificationAttempt{}, LastGood: []generated.BackupLastGood{}, RecoveryEpoch: plan.Binding.RecoveryEpoch}}
	config := BackupOperations{Drafts: &backupDraftServiceStub{}, Status: status, Runs: RunOperationConfig{Runs: runs, Plans: runs, Acknowledgements: runs, Results: app.config.Results, Authorization: app.effective}, Results: app.config.Results}
	if err := RegisterBackupOperations(app, config); err != nil {
		t.Fatal(err)
	}
	base := generated.BackupVerifyRequest{Schema: generated.SchemaIDBackupVerifyRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, TargetDigest: plan.Operations[0].InputDigest, IdempotencyKey: "backup-verify-test", JobID: "job-test", PointID: point, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, HumanAcknowledgementID: "ack-test"}
	for _, test := range []struct {
		name   string
		mutate func(*generated.BackupVerifyRequest)
		want   int
	}{
		{"wrong-point", func(input *generated.BackupVerifyRequest) { input.PointID = "other-point" }, http.StatusConflict},
		{"wrong-plan", func(input *generated.BackupVerifyRequest) { input.PlanDigest = "sha256:" + strings.Repeat("0", 64) }, http.StatusConflict},
		{"wrong-ack", func(input *generated.BackupVerifyRequest) { input.HumanAcknowledgementID = "other-ack" }, http.StatusPreconditionFailed},
		{"exact", func(*generated.BackupVerifyRequest) {}, http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := base
			test.mutate(&input)
			body, _ := json.Marshal(input)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/backups/job-test/verify", strings.NewReader(string(body)))
			request.Header.Set("Content-Type", "application/json")
			request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-run-test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
			response := httptest.NewRecorder()
			app.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
		})
	}
	if runs.submitCalls != 1 {
		t.Fatalf("submits=%d; invalid requests bypassed plan", runs.submitCalls)
	}
}
