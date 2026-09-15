//go:build linux

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func gateAPIFixture(t *testing.T) (*Application, *store.GateRepository, *store.PlanRepository) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: filepath.Join(directory, "control.db"), Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "0.0.0-test", BuildVersion: "build-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := authority.Close(); err != nil {
			t.Error(err)
		}
	})
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "0.0.0-test", ReleaseBuildID: "build-test"}, func() (string, error) { return "request-gate-integration", nil })
	app, err := NewApplication(Config{Authority: authority, Authorizer: allowOperationAuthorizer(), Reads: testReads{}, Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	effective := &effectiveAuthorizationStub{}
	app.effective = EffectiveAuthorizationConfig{Authorizer: effective, Recorder: effective, Clock: time.Now}
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	gates := store.NewGateRepository(authority)
	revisions := store.NewPlanRepository(authority)
	if err := RegisterGateOperations(app, GateOperations{Gates: gates, Revisions: revisions, Declarations: declarations, Results: factory, Build: result.BuildInfo{ToolVersion: "0.0.0-test", ReleaseBuildID: "build-test"}, Clock: func() time.Time { return time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC) }}); err != nil {
		t.Fatal(err)
	}
	return app, gates, revisions
}

func serveGateRequest(t *testing.T, app *Application, method, path string, input any) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if input != nil {
		var err error
		body, err = json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	return response
}

func TestGateProfileDraftAPIIsInertRevisionBoundAndHasNoSetter(t *testing.T) {
	app, gates, revisions := gateAPIFixture(t)
	scope := store.GateAppliedProfile{ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0", Capabilities: []string{}}
	digest, err := store.ProfileScopeDigest(scope)
	if err != nil {
		t.Fatal(err)
	}
	request := generated.GateProfileDraftRequest{Schema: generated.SchemaIDGateProfileDraftRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 0, RecoveryEpoch: 0, TargetDigest: digest, IdempotencyKey: "key-profile-a", BindingID: "binding-a", ProfileID: scope.ProfileID, ProfileVersion: scope.ProfileVersion, PolicyID: scope.PolicyID, PolicyVersion: scope.PolicyVersion, Capabilities: []string{}}
	stale := request
	stale.ExpectedStateRevision = 1
	if response := serveGateRequest(t, app, http.MethodPost, "/api/v1/gates/profile-drafts", stale); response.Code != http.StatusConflict {
		t.Fatalf("stale revision=%d %s", response.Code, response.Body.String())
	}
	stale = request
	stale.RecoveryEpoch = 1
	if response := serveGateRequest(t, app, http.MethodPost, "/api/v1/gates/profile-drafts", stale); response.Code != http.StatusConflict {
		t.Fatalf("wrong epoch=%d %s", response.Code, response.Body.String())
	}
	private := request
	private.Capabilities = []string{"secret://private-canary"}
	response := serveGateRequest(t, app, http.MethodPost, "/api/v1/gates/profile-drafts", private)
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "private-canary") {
		t.Fatalf("private input=%d %s", response.Code, response.Body.String())
	}
	token, err := revisions.CurrentRevision(context.Background())
	if err != nil || token.StateRevision != 0 {
		t.Fatalf("rejected draft mutated: %#v %v", token, err)
	}
	response = serveGateRequest(t, app, http.MethodPost, "/api/v1/gates/profile-drafts", request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"draft"`) || !strings.Contains(response.Body.String(), `"changeId":"gate-profile-binding-a"`) {
		t.Fatalf("profile draft=%d %s", response.Code, response.Body.String())
	}
	if _, err := gates.GetAppliedProfileScope(context.Background()); store.Code(err) != generated.ErrorCodeResourceNotFound {
		t.Fatalf("draft became applied: %v", err)
	}
	token, err = revisions.CurrentRevision(context.Background())
	if err != nil || token.StateRevision != 2 {
		t.Fatalf("draft/declaration revision=%#v %v", token, err)
	}
	if response := serveGateRequest(t, app, http.MethodPost, "/api/v1/gates/profile-drafts/binding-a/bind", nil); response.Code != http.StatusNotFound {
		t.Fatalf("direct bind=%d %s", response.Code, response.Body.String())
	}
	listed := serveGateRequest(t, app, http.MethodGet, "/api/v1/gates", nil)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"applied-profile-missing"`) || strings.Contains(listed.Body.String(), `"outcome":"passed"`) {
		t.Fatalf("inert list=%d %s", listed.Code, listed.Body.String())
	}
}

func TestGateEvidenceAPIOnlyAuthorsFixtureDraftAndRejectsPrivateAttachments(t *testing.T) {
	app, gates, revisions := gateAPIFixture(t)
	digest := "sha256:" + strings.Repeat("a", 64)
	bundle := generated.GateEvidenceBundle{Schema: generated.SchemaIDGateEvidenceBundle, SchemaVersion: "1.1.0", Facts: []generated.GateEvidenceFact{}, Checks: []generated.GateEvidenceCheck{}, Attachments: []generated.GateEvidenceAttachment{}, CollectorID: "collector-a", ObservedAt: "2026-09-15T08:00:00Z"}
	request := generated.GateEvidenceRequest{Schema: generated.SchemaIDGateEvidenceRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 0, RecoveryEpoch: 0, TargetDigest: digest, IdempotencyKey: "key-evidence-a", EvidenceID: "evidence-a", GateID: "G-008", SubjectID: "site-a", DefinitionVersion: "1.0.0", EvaluatorVersion: "1.0.0", ArtifactDigest: digest, ObservedAt: bundle.ObservedAt, Bundle: bundle}
	private := request
	private.Bundle.Attachments = []generated.GateEvidenceAttachment{{Schema: generated.SchemaIDGateEvidenceAttachment, SchemaVersion: "1.1.0", Digest: digest, SizeBytes: 1, MediaType: "text/plain"}}
	if response := serveGateRequest(t, app, http.MethodPost, "/api/v1/gates/G-008/evidence", private); response.Code != http.StatusBadRequest {
		t.Fatalf("attachment=%d %s", response.Code, response.Body.String())
	}
	if response := serveGateRequest(t, app, http.MethodPost, "/api/v1/gates/G-009/evidence", request); response.Code != http.StatusBadRequest {
		t.Fatalf("wrong gate path=%d %s", response.Code, response.Body.String())
	}
	response := serveGateRequest(t, app, http.MethodPost, "/api/v1/gates/G-008/evidence", request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"draft"`) {
		t.Fatalf("evidence draft=%d %s", response.Code, response.Body.String())
	}
	draft, err := gates.GetGateDraft(context.Background(), "evidence-a")
	if err != nil || draft.SourceKind != "fixture" || draft.ProofClass != "fixture" {
		t.Fatalf("source self-issued: %#v %v", draft, err)
	}
	applied, err := gates.ListAppliedGateEvidence(context.Background(), "G-008", "site-a")
	if err != nil || len(applied) != 0 {
		t.Fatalf("draft became evidence: %d %v", len(applied), err)
	}
	token, err := revisions.CurrentRevision(context.Background())
	if err != nil || token.StateRevision != 2 {
		t.Fatalf("inert revisions=%#v %v", token, err)
	}
}
