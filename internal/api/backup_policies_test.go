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
			Schema: generated.SchemaIDBackupPolicy, SchemaVersion: "1.1.0",
			PolicyID: "policy-a", OwnerID: "owner-a", SourceID: "source-a",
			SourceSelectors: []string{"selector-a"}, ConsistencyHookID: "sqlite-online",
			RepositoryID: &repo, RepositoryClass: "standard", ScheduleIntent: "daily",
			ExpectedBytes: 1024, ExpectedGrowthBytes: 512, MinimumFreeBytes: 4096,
			EncryptionKeyReferenceID: &enc, RecoveryKeyReferenceID: &rec,
			RetentionDays: 7, RestoreTargetID: "restore-a",
			Dependencies:           []generated.BackupDependency{{DependencyID: "dep-a", Kind: "binary", Digest: digest}},
			FunctionalTestRequired: true, RecoveryEpoch: 0, Revision: 1,
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
