//go:build linux

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type auditAcceptanceAuthorizer struct{}

func (auditAcceptanceAuthorizer) AuthorizeRead(_ context.Context, principal identity.Principal, target authorization.ReadTarget) (authorization.ReadScope, error) {
	return authorization.ReadScope{PrincipalID: principal.ID, Capability: target.Capability, ResourceKind: target.ResourceKind, GrantRevision: 1, ScopeDigest: "sha256:" + strings.Repeat("a", 64)}, nil
}

func TestAuditVerificationRouteKeepsEmptyLocalCoreReadableWithoutIndependentAdapter(t *testing.T) {
	directory := shortServerTempDir(t)
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: filepath.Join(directory, "control.db"), Mode: store.InitializeNew, ExpectedUID: uint32(os.Getuid()), ToolVersion: "audit-test", BuildVersion: "audit-test"})
	if err != nil {
		t.Fatal(err)
	}
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "audit-test", ReleaseBuildID: "audit-test"}, func() (string, error) { return "request-audit-acceptance", nil })
	application, err := api.NewApplication(api.Config{Authority: authority, Authorizer: auditAcceptanceAuthorizer{}, Reads: store.NewReadRepository(authority), Results: factory})
	if err != nil {
		t.Fatal(err)
	}
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := api.RegisterAuditOperations(application, api.AuditOperations{Audit: authority, Revisions: store.NewPlanRepository(authority), Declarations: declarations, Results: factory}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.Shutdown(context.Background()) })
	request := httptest.NewRequest(http.MethodGet, "/api/v1/audit-history/verification", nil)
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "principal.audit", Method: identity.LocalOSPeerMethod}))
	response := httptest.NewRecorder()
	application.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"degraded"`) || !strings.Contains(response.Body.String(), `"reasonCode":"audit-history-empty"`) || strings.Contains(response.Body.String(), "private-audit-fixture") {
		t.Fatalf("audit verification response = %d %s", response.Code, response.Body.String())
	}
}
