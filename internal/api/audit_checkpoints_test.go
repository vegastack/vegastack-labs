package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestAuditCheckpointDenialUsesCollectionTargetBeforeBodyRead(t *testing.T) {
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-audit-denied", nil })
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: allowOperationAuthorizer(), Reads: testReads{}, Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	denied := &effectiveAuthorizationStub{decision: authorization.Decision{ReasonCode: authorization.ReasonGrantMissing}}
	app.effective = EffectiveAuthorizationConfig{Authorizer: denied, Recorder: denied, Clock: time.Now}
	if err := RegisterAuditOperations(app, AuditOperations{Audit: auditAPIRepository{}, Revisions: auditAPIRevision{}, Declarations: auditAPIDeclarations{}, Results: factory}); err != nil {
		t.Fatal(err)
	}
	body := &countingBody{data: bytes.NewReader([]byte(`{"privateCanary":"must-not-read"}`))}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/audit-checkpoints", nil)
	request.Body = body
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || body.reads != 0 || len(denied.records) != 1 || denied.records[0].Decision.Target.ResourceID != "audit-checkpoints" || strings.Contains(response.Body.String(), "privateCanary") {
		t.Fatalf("status=%d reads=%d records=%#v body=%s", response.Code, body.reads, denied.records, response.Body.String())
	}
}

func TestBrowserAuditVerificationStatusMapping(t *testing.T) {
	for _, test := range []struct{ input, want, next string }{
		{"pending", "pending", "collect an independent audit checkpoint"},
		{"healthy", "anchored", "none"},
		{"anchored", "anchored", "none"},
		{"degraded", "degraded", "collect and compare an independent audit checkpoint"},
		{"incident", "incident", "investigate the audit integrity incident"},
	} {
		got, next, ok := browserAuditVerificationStatus(test.input)
		if !ok || got != test.want || next != test.next {
			t.Fatalf("%q => %q/%q/%v", test.input, got, next, ok)
		}
	}
	if _, _, ok := browserAuditVerificationStatus("private-state"); ok {
		t.Fatal("unknown audit status was projected")
	}
}

type auditAPIRepository struct {
	checkpoints  []generated.AuditCheckpoint
	verification generated.AuditVerificationData
	verifyErr    error
}

func (repository auditAPIRepository) ListAuditCheckpoints(context.Context) ([]generated.AuditCheckpoint, error) {
	return append([]generated.AuditCheckpoint{}, repository.checkpoints...), nil
}
func (repository auditAPIRepository) ListAuditCheckpointsPageScoped(context.Context, authorization.ReadScope, store.RevisionToken, string, int) ([]generated.AuditCheckpoint, error) {
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

type mutableAuditAPIRevision struct{ token store.RevisionToken }

func (revision *mutableAuditAPIRevision) CurrentRevision(context.Context) (store.RevisionToken, error) {
	return revision.token, nil
}

type pagedAuditAPIRepository struct{ auditAPIRepository }

func (repository pagedAuditAPIRepository) ListAuditCheckpointsPageScoped(_ context.Context, _ authorization.ReadScope, _ store.RevisionToken, afterID string, limit int) ([]generated.AuditCheckpoint, error) {
	items := repository.checkpoints
	for len(items) > 0 && items[0].CheckpointID <= afterID {
		items = items[1:]
	}
	if len(items) > limit {
		items = items[:limit]
	}
	return append([]generated.AuditCheckpoint{}, items...), nil
}

func TestAuditCheckpointListPagesAndRejectsChangedSnapshot(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	checkpoint := func(id string, first int64) generated.AuditCheckpoint {
		return generated.AuditCheckpoint{Schema: generated.SchemaIDAuditCheckpoint, SchemaVersion: "1.1.0", CheckpointID: id, FirstEventID: first, LastEventID: first, ChainDigest: digest, Status: "pending", ReasonCode: "checkpoint-pending", SourceKind: "fixture", ProofClass: "fixture", VerificationStatus: "pending", RecoveryEpoch: 0}
	}
	repository := pagedAuditAPIRepository{auditAPIRepository{checkpoints: []generated.AuditCheckpoint{checkpoint("checkpoint-a", 1), checkpoint("checkpoint-b", 2)}}}
	revisions := &mutableAuditAPIRevision{}
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-audit-page", nil })
	codec, err := NewCursorCodec(bytes.NewReader(bytes.Repeat([]byte{9}, 32)), func() time.Time { return time.Date(2026, 9, 24, 6, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: allowOperationAuthorizer(), Reads: testReads{}, Results: factory, Cursors: codec})
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterAuditOperations(app, AuditOperations{Audit: repository, Revisions: revisions, Declarations: auditAPIDeclarations{}, Results: factory}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/audit-checkpoints?limit=1", nil)
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	var envelope struct {
		Data generated.BrowserAuditCheckpointListData `json:"data"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &envelope) != nil || len(envelope.Data.Items) != 1 || envelope.Data.NextCursor == nil {
		t.Fatalf("first page status=%d body=%s", response.Code, response.Body.String())
	}
	cursor := *envelope.Data.NextCursor
	second := httptest.NewRequest(http.MethodGet, "/api/v1/audit-checkpoints?limit=1&cursor="+url.QueryEscape(cursor), nil)
	second = second.WithContext(identity.WithVerifiedPrincipal(second.Context(), identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}))
	secondResponse := httptest.NewRecorder()
	app.ServeHTTP(secondResponse, second)
	if secondResponse.Code != http.StatusOK || !strings.Contains(secondResponse.Body.String(), "checkpoint-b") {
		t.Fatalf("second page status=%d body=%s", secondResponse.Code, secondResponse.Body.String())
	}
	revisions.token.StateRevision = 1
	staleResponse := httptest.NewRecorder()
	app.ServeHTTP(staleResponse, second)
	if staleResponse.Code != http.StatusConflict {
		t.Fatalf("stale cursor status=%d body=%s", staleResponse.Code, staleResponse.Body.String())
	}
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
