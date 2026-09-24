//go:build linux

package server_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/schedule"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type phase5ScheduleStore struct{ policy generated.ScheduledJobPolicy }

func (fixture phase5ScheduleStore) StageDraft(context.Context, generated.ScheduledJobPolicy, audit.Attribution) (store.ScheduledPolicyDraft, error) {
	return store.ScheduledPolicyDraft{}, nil
}
func (fixture phase5ScheduleStore) GetActivePolicy(context.Context, string) (generated.ScheduledJobPolicy, error) {
	return fixture.policy, nil
}
func (fixture phase5ScheduleStore) ListActivePolicies(_ context.Context, _ authorization.ReadScope, snapshot store.RevisionToken, _ string, _ int) ([]generated.ScheduledJobPolicy, store.RevisionToken, error) {
	return []generated.ScheduledJobPolicy{fixture.policy}, snapshot, nil
}
func (phase5ScheduleStore) ListOccurrences(_ context.Context, _ authorization.ReadScope, snapshot store.RevisionToken, _ string, _ int) ([]generated.ScheduledJob, store.RevisionToken, error) {
	return []generated.ScheduledJob{}, snapshot, nil
}
func (fixture phase5ScheduleStore) CurrentScheduleRevision(context.Context) (schedule.Revision, error) {
	return schedule.Revision{StateRevision: fixture.policy.StateRevision, RecoveryEpoch: fixture.policy.RecoveryEpoch}, nil
}

type phase5ScheduleDispatch struct{}

func (phase5ScheduleDispatch) Dispatch(context.Context, schedule.DispatchRequest) (generated.ScheduledJob, error) {
	return generated.ScheduledJob{}, nil
}
func (phase5ScheduleDispatch) Cancel(context.Context, string) (generated.ScheduledJob, error) {
	return generated.ScheduledJob{}, nil
}

type phase5ScheduleRunner struct{}

func (phase5ScheduleRunner) Run(context.Context, generated.ScheduledJob, audit.Attribution) (generated.ScheduledJob, error) {
	return generated.ScheduledJob{}, nil
}

type phase5ReadAuthorizer struct{}

func (phase5ReadAuthorizer) AuthorizeRead(_ context.Context, principal identity.Principal, target authorization.ReadTarget) (authorization.ReadScope, error) {
	return authorization.ReadScope{PrincipalID: principal.ID, Capability: target.Capability, ResourceKind: target.ResourceKind, GrantRevision: 1, ScopeDigest: "sha256:" + strings.Repeat("f", 64)}, nil
}

func TestPhase5ScheduleProjectionComposesRealAPIAndLocalClient(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "vsk-phase5-compose-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: filepath.Join(directory, "control.db"), Mode: store.InitializeNew, ExpectedUID: uint32(os.Getuid()), ToolVersion: "phase5-test", BuildVersion: "phase5-test"})
	if err != nil {
		t.Fatal(err)
	}
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "phase5-test", ReleaseBuildID: "phase5-test"}, func() (string, error) { return "request-phase5-compose", nil })
	application, err := api.NewApplication(api.Config{Authority: authority, Authorizer: phase5ReadAuthorizer{}, Reads: store.NewReadRepository(authority), Results: factory})
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	policy := generated.ScheduledJobPolicy{Schema: generated.SchemaIDScheduledJobPolicy, SchemaVersion: "1.1.0", PolicyID: "policy-a", Revision: 3, DeclarationID: "declaration-a", DeclarationRevision: 1, ActionKind: "gate-check", OperationType: "schedule.gate.check", AdapterID: "core.schedule-observe", ExactSourceIDs: []string{"source-a"}, ExactSubjectIDs: []string{"subject-a"}, ExactTargetIDs: []string{"target-a"}, MaximumWork: 1, CredentialReferenceIDs: []string{}, GrantRevision: 1, StateRevision: 0, RecoveryEpoch: 0, PolicyVersion: "1.0.0", RetentionRuleDigest: digest, AnchorAt: "2026-09-24T00:00:00Z", IntervalSeconds: 3600, WindowSeconds: 1800, CatchUp: "none", Concurrency: "forbid", MaxAttempts: 1, InitialBackoffSeconds: 1, MaximumBackoffSeconds: 1, ExpiresAt: "2026-09-25T00:00:00Z", Enabled: true}
	if err := api.RegisterScheduleOperations(application, api.ScheduleOperations{Policies: phase5ScheduleStore{policy: policy}, Dispatch: phase5ScheduleDispatch{}, Runner: phase5ScheduleRunner{}, Results: factory}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.Shutdown(context.Background()) })
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		principal := identity.Principal{ID: "principal.phase5", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
		application.ServeHTTP(writer, request.WithContext(identity.WithVerifiedPrincipal(request.Context(), principal)))
	})

	browserRequest := httptest.NewRequest(http.MethodGet, "/api/v1/scheduled-job-policies/policy-a", nil)
	browserResponse := httptest.NewRecorder()
	handler.ServeHTTP(browserResponse, browserRequest)
	if browserResponse.Code != http.StatusOK {
		t.Fatalf("browser response=%d %s", browserResponse.Code, browserResponse.Body.String())
	}
	var browserEnvelope struct {
		Data generated.BrowserScheduledJobPolicy `json:"data"`
	}
	if err := json.Unmarshal(browserResponse.Body.Bytes(), &browserEnvelope); err != nil {
		t.Fatal(err)
	}

	socketPath := filepath.Join(directory, "control.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = listener.Close() })
	cliResponse, err := localapi.NewClient(factory).GetScheduledPolicy(context.Background(), serverconfig.Profile{SocketPath: socketPath}, "policy-a")
	if err != nil {
		t.Fatal(err)
	}
	if cliResponse.Data != browserEnvelope.Data || cliResponse.Data.TargetDigest == "" || strings.Contains(string(cliResponse.Raw), "target-a") {
		t.Fatalf("surface mismatch: browser=%#v cli=%#v raw=%s", browserEnvelope.Data, cliResponse.Data, cliResponse.Raw)
	}
}

func TestPhase5BrowserCanReadSafeFactsAndCannotReachProtectedEffects(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"/api/v1/backups/status",
		"/api/v1/recovery-points",
		"/api/v1/audit-checkpoints",
		"/api/v1/audit-history/verification",
		"/api/v1/restore-plans",
		"/api/v1/scheduled-job-policies",
		"/api/v1/scheduled-jobs",
	} {
		if !api.RemoteReadRequestAllowed(http.MethodGet, path) {
			t.Errorf("browser-safe Phase 5 read denied: %s", path)
		}
	}

	for _, path := range []string{
		"/api/v1/backup-policies/policy-a/jobs",
		"/api/v1/recovery-points/point-a/verifications",
		"/api/v1/restore-plans/restore-a/runs",
		"/api/v1/restore-plans/restore-a/verifications",
		"/api/v1/scheduled-job-policies/policy-a/occurrences",
		"/api/v1/audit-checkpoints",
	} {
		if api.RemoteReadRequestAllowed(http.MethodPost, path) {
			t.Errorf("browser reached protected Phase 5 effect: %s", path)
		}
	}

	for _, path := range []string{
		"/api/v1/gates/G-008/check",
		"/api/v1/gates/G-008/evidence",
		"/api/v1/recovery-points/point-a/restore-drafts",
	} {
		if !api.RemoteReadRequestAllowed(http.MethodPost, path) {
			t.Errorf("reviewed inert browser mutation denied: %s", path)
		}
	}
}

func TestPhase5ConstrainedSSHUsesGeneratedOperatorAllowlist(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"/api/v1/backup-policies/policy-a/jobs",
		"/api/v1/recovery-points/point-a/verifications",
		"/api/v1/recovery-points/point-a/restore-plans",
		"/api/v1/restore-plans/restore-a/runs",
		"/api/v1/restore-plans/restore-a/verifications",
		"/api/v1/scheduled-job-policies/policy-a/occurrences",
	} {
		if !api.ConstrainedSSHRequestAllowed(http.MethodPost, path) {
			t.Errorf("generated operator route absent from constrained SSH: %s", path)
		}
	}

	for _, path := range []string{
		"/api/v1/credential-references/ref-a/import-stream",
		"/api/v1/database/exports/raw",
		"/api/v1/session",
	} {
		if api.ConstrainedSSHRequestAllowed(http.MethodPost, path) {
			t.Errorf("forbidden constrained SSH route admitted: %s", path)
		}
	}
}
