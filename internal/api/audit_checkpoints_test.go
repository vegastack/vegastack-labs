package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type auditAPIRepository struct {
	checkpoints  []generated.AuditCheckpoint
	verification generated.AuditVerificationData
	verifyErr    error
}

func (repository auditAPIRepository) ListAuditCheckpoints(context.Context) ([]generated.AuditCheckpoint, error) {
	return append([]generated.AuditCheckpoint{}, repository.checkpoints...), nil
}
func (repository auditAPIRepository) VerifyAuditHistory(context.Context, adapter.CheckpointReader) (generated.AuditVerificationData, error) {
	return repository.verification, repository.verifyErr
}
func (auditAPIRepository) ChainRange(context.Context, audit.EventID, audit.EventID) (audit.ChainRange, error) {
	return audit.ChainRange{}, errors.New("not used")
}

type auditAPIRevision struct{ token store.RevisionToken }

func (revision auditAPIRevision) CurrentRevision(context.Context) (store.RevisionToken, error) {
	return revision.token, nil
}

type auditAPIDeclarations struct{}

func (auditAPIDeclarations) Revise(context.Context, change.AuthorScope, generated.DeclarationRevisionRequest) (change.Result, error) {
	return change.Result{}, errors.New("not used")
}
func (auditAPIDeclarations) Get(context.Context, string, int64) (generated.DeclarationRevision, error) {
	return generated.DeclarationRevision{}, errors.New("not used")
}

func TestAuditVerificationSurfacesNeverExposePrivatePayload(t *testing.T) {
	const privateCanary = "private-audit-fixture"
	digest := "sha256:" + strings.Repeat("a", 64)
	independent := "sha256:" + strings.Repeat("b", 64)
	repository := auditAPIRepository{verification: generated.AuditVerificationData{
		Schema: generated.SchemaIDAuditVerificationData, SchemaVersion: "1.1.0", Status: "incident", InstanceID: "instance-a",
		RecoveryEpoch: 2, LocalDigest: digest, IndependentDigest: &independent, IndependentMatch: false, LastAnchoredSequence: 7,
		ReasonCode: "independent-checkpoint-ahead", PreAnchor: false,
	}, verifyErr: errors.New(privateCanary)}
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-audit-test", nil })
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: allowOperationAuthorizer(), Reads: testReads{}, Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterAuditOperations(app, AuditOperations{Audit: repository, Revisions: auditAPIRevision{store.RevisionToken{StateRevision: 7, RecoveryEpoch: 2}}, Declarations: auditAPIDeclarations{}, Results: factory}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/audit-history/verification", nil)
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), privateCanary) || !strings.Contains(response.Body.String(), "independent-checkpoint-ahead") || !strings.Contains(response.Body.String(), `"status":"incident"`) {
		t.Fatalf("unsafe verification response = %d %s", response.Code, response.Body.String())
	}
}

var _ authorization.ReadAuthorizer = allowOperationAuthorizer()
