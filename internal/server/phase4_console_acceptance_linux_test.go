//go:build linux

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/consoleassets"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"golang.org/x/sys/unix"
)

func TestPhase4ConsoleSocketPathFitsProtectedLinuxTempRoot(t *testing.T) {
	const testName = "TestPhase4ConsoleChangesCompleteApprovedResumeAndCancelLoopsOverRealTLS"
	tooLong := filepath.Join("/var/tmp/vsk.8yrYX6", testName+"123456789", "001", "control.sock")
	if len(tooLong) < len(unix.RawSockaddrUnix{}.Path) {
		t.Fatal("protected-runner reproduction no longer exceeds the Linux Unix socket path limit")
	}
	socketPath := phase4ConsoleSocketPath(t)
	if len(socketPath) >= len(unix.RawSockaddrUnix{}.Path) {
		t.Fatalf("phase 4 console socket path is too long: %d bytes", len(socketPath))
	}
	if strings.Contains(socketPath, testName) {
		t.Fatal("phase 4 console socket path inherited the long Go test name")
	}
}

func phase4ConsoleSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "vsk4-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove phase 4 socket directory: %v", err)
		}
	})
	socketPath := filepath.Join(directory, "control.sock")
	if len(socketPath) >= len(unix.RawSockaddrUnix{}.Path) {
		t.Fatalf("phase 4 console socket path exceeds the Linux limit: %d bytes", len(socketPath))
	}
	return socketPath
}

type phase4ApprovalBridge struct {
	mu      sync.Mutex
	cards   map[string]acknowledgement.RequestCard
	service *acknowledgement.Service
	clock   func() time.Time
}

func (bridge *phase4ApprovalBridge) Resolve(context.Context, generated.AcknowledgementRequest) (acknowledgement.Scope, error) {
	return acknowledgement.Scope{}, apiFailureForTest(generated.ErrorCodeAuthorizationDenied)
}

func (bridge *phase4ApprovalBridge) ResolvePlan(_ context.Context, plan generated.Plan) (acknowledgement.Scope, error) {
	return acknowledgement.Scope{
		Human:       identity.Principal{ID: "human.console", Kind: identity.PrincipalHuman, Method: identity.SlackSocketModeMethod},
		AuthorityID: "authority.console",
		Nonce:       "server-owned-console-nonce-" + plan.PlanID,
	}, nil
}

func (bridge *phase4ApprovalBridge) Publish(_ context.Context, card acknowledgement.RequestCard) error {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	bridge.cards[card.Request.PlanID] = card
	return nil
}

func (bridge *phase4ApprovalBridge) approve(ctx context.Context, planID string) error {
	bridge.mu.Lock()
	card, ok := bridge.cards[planID]
	bridge.mu.Unlock()
	if !ok {
		return apiFailureForTest(generated.ErrorCodeResourceNotFound)
	}
	expiresAt, err := time.Parse(time.RFC3339, card.Request.ExpiresAt)
	if err != nil {
		return err
	}
	_, err = bridge.service.Decide(ctx, acknowledgement.Candidate{
		Human:       identity.Principal{ID: card.Request.HumanID, Kind: identity.PrincipalHuman, Method: identity.SlackSocketModeMethod},
		AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove,
		PlanID: card.Request.PlanID, PlanDigest: card.Request.PlanDigest, TargetDigest: card.Request.TargetDigest,
		ReasonDigest: card.Request.ReasonDigest, Nonce: card.Nonce, StateRevision: card.Request.StateRevision,
		RecoveryEpoch: card.Request.RecoveryEpoch, ExpiresAt: expiresAt, DecidedAt: bridge.clock().UTC().Truncate(time.Second),
	})
	return err
}

type phase4ResumableAdapter struct {
	mu       sync.Mutex
	attempts map[string]int
}

func (fixture *phase4ResumableAdapter) Execute(_ context.Context, operation adapter.Operation) (adapter.Effect, error) {
	fixture.mu.Lock()
	fixture.attempts[operation.OperationID]++
	attempt := fixture.attempts[operation.OperationID]
	fixture.mu.Unlock()
	if attempt == 1 {
		return adapter.Effect{Status: "failed", ResultDigest: phase4Digest("e"), EffectObserved: false}, context.Canceled
	}
	return adapter.Effect{Status: "succeeded", ResultDigest: phase4Digest("f"), Changed: true, EffectObserved: true}, nil
}

func (*phase4ResumableAdapter) Verify(context.Context, adapter.Operation, adapter.Effect) (adapter.Verification, error) {
	return adapter.Verification{Verified: true, Digest: phase4Digest("a")}, nil
}

func TestPhase4ConsoleChangesCompleteApprovedResumeAndCancelLoopsOverRealTLS(t *testing.T) {
	clock := &browserIntegrationClock{at: time.Date(2030, 9, 13, 8, 0, 0, 0, time.UTC)}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "phase4-console-key"
	keyServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"}}})
	}))
	t.Cleanup(keyServer.Close)
	assertion := signBrowserIntegrationJWT(t, key, keyID, keyServer.URL, clock.Now(), time.Hour)
	verified := identity.VerifiedIdentity{Issuer: keyServer.URL, Subject: "subject-real-browser", Audiences: []string{"aud-console"}, IssuedAt: clock.Now().Add(-time.Minute), ExpiresAt: clock.Now().Add(time.Hour), Method: identity.CloudflareAccessMethod}
	binding, err := identity.BindingDigest(verified)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "control.db")
	config := store.Config{DatabasePath: databasePath, Mode: store.InitializeNew, ExpectedUID: uint32(os.Getuid()), ToolVersion: "phase4-test", BuildVersion: "phase4-test", Clock: clock.Now}
	authority, err := store.Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	seedBrowserIntegrationAuthority(t, databasePath, binding, clock.Now())
	seedPhase4ConsoleGrants(t, databasePath, clock.Now())
	seedPhase4BrowserChangeGrants(t, databasePath, clock.Now())
	config.Mode = store.OpenExisting
	authority, err = store.Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })

	certificatePath, keyPath := writeRemoteTestCertificate(t)
	listener, err := RemoteListen(context.Background(), RemoteListenConfig{Address: "127.0.0.1:0", CertificatePath: certificatePath, PrivateKeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "https://" + listener.Addr().String()
	var requestSequence atomic.Uint64
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "phase4-test", ReleaseBuildID: "phase4-test"}, func() (string, error) {
		return fmt.Sprintf("request-phase4-console-%d", requestSequence.Add(1)), nil
	})
	identities, err := identity.NewCloudflareAccessAdapter(identity.CloudflareAccessConfig{Issuer: keyServer.URL, Audience: "aud-console", CertificatesURL: keyServer.URL + "/cdn-cgi/access/certs", ClockSkew: time.Minute, MaxTokenBytes: 16 * 1024, KnownKeyOutageLimit: time.Hour}, keyServer.Client(), clock.Now)
	if err != nil || identities.Refresh(context.Background()) != nil {
		t.Fatal("identity fixture failed")
	}
	authenticator, err := NewBrowserAuthenticator(BrowserAuthConfig{ExactOrigin: baseURL, ExactHost: listener.Addr().String(), Identities: identities, Sessions: authority, Results: factory})
	if err != nil {
		t.Fatal(err)
	}
	readAuthorizer := newAuditingReadAuthorizer(store.NewReadAuthorizer(authority), authority)
	application, err := api.NewApplication(api.Config{Authority: authority, Authorizer: readAuthorizer, Reads: store.NewReadRepository(authority), Results: factory, Sessions: authenticator.SessionService()})
	if err != nil {
		t.Fatal(err)
	}
	effective := store.NewEffectiveAuthorizationRepository(authority)
	effectiveConfig := api.EffectiveAuthorizationConfig{Authorizer: authorization.NewEvaluator(effective), Recorder: effective, Clock: clock.Now}
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	plansRepository := store.NewPlanRepository(authority)
	observations, err := planengine.NewStateObservationReader(plansRepository)
	if err != nil {
		t.Fatal(err)
	}
	plans, err := planengine.NewService(planengine.Config{Repository: plansRepository, Observations: observations, Clock: clock.Now, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "routine", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if err != nil {
		t.Fatal(err)
	}
	if err := api.RegisterDeclarationPlanOperations(application, api.DeclarationPlanConfig{Declarations: declarations, Plans: plans, Results: factory, Authorization: effectiveConfig}); err != nil {
		t.Fatal(err)
	}
	acknowledgements, err := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(authority), Plans: acknowledgementPlanReader{plans: plans}, Authorizer: authorization.NewEvaluator(effective), Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	bridge := &phase4ApprovalBridge{cards: map[string]acknowledgement.RequestCard{}, service: acknowledgements, clock: clock.Now}
	if err := api.RegisterAcknowledgementOperations(application, api.AcknowledgementOperationConfig{Plans: plans, Acknowledgements: acknowledgements, Scopes: bridge, Publisher: bridge, Results: factory}); err != nil {
		t.Fatal(err)
	}
	registry := adapter.NewRegistry()
	if err := registry.Register("adapter-console", &phase4ResumableAdapter{attempts: map[string]int{}}); err != nil {
		t.Fatal(err)
	}
	runs, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(authority), Plans: plans, Admission: runengine.NewAdmissionGate(acknowledgements, clock.Now), Adapters: registry, Clock: clock.Now, ExecutionContext: context.Background()})
	if err != nil {
		t.Fatal(err)
	}
	if err := api.RegisterRunOperations(application, api.RunOperationConfig{Runs: runs, Plans: plans, Acknowledgements: acknowledgements, Results: factory, Authorization: effectiveConfig}); err != nil {
		t.Fatal(err)
	}
	files, manifest, err := consoleassets.Open()
	if err != nil {
		t.Fatal(err)
	}
	console, err := NewConsoleHandler(files, manifest)
	if err != nil {
		t.Fatal(err)
	}
	socketPath := phase4ConsoleSocketPath(t)
	serviceProfile := serverconfig.Profile{SocketPath: socketPath, InventoryExportRoot: directory, SocketOwnerUID: uint32(os.Getuid()), SocketMode: 0o600, ShutdownGrace: 5 * time.Second, PrincipalBindings: []identity.Binding{{UID: uint32(os.Getuid()), PrincipalID: "principal.local"}}, RemoteRead: serverconfig.RemoteRead{Enabled: true, ConfigurationValid: true}}
	service, err := New(Config{Profile: serviceProfile, Application: application, Results: factory, PlatformProbe: staticPlatformProbe{platform: testSupportedPlatform()}, Remote: &RemoteConfig{Authenticator: authenticator, Console: console, ListenConfig: RemoteListenConfig{Address: listener.Addr().String(), CertificatePath: certificatePath, PrivateKeyPath: keyPath}, ListenerFactory: func(context.Context, RemoteListenConfig) (net.Listener, error) { return listener, nil }}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	cliConfigPath := filepath.Join(directory, "cli-server-profile.json")
	writeProtectedJSON(t, cliConfigPath, generated.ServerProfile{
		Schema: generated.SchemaIDServerProfile, SchemaVersion: "1.3.0", SocketPath: socketPath,
		SocketOwnerUID: int64(os.Getuid()), SocketMode: "0600", ShutdownGraceSeconds: 5,
		InventoryExportRoot: directory, PrincipalBindings: []generated.LocalPrincipalBinding{{UID: int64(os.Getuid()), PrincipalID: "principal.local"}},
		RemoteRead: generated.RemoteReadProfile{Enabled: false},
	})

	controller := httptest.NewServer(phase4Controller(t, databasePath, bridge, clock.Now, os.Getenv("VSK_PHASE3_BINARY"), cliConfigPath))
	t.Cleanup(func() {
		controller.Close()
		cancel()
		if runErr := <-done; runErr != nil {
			t.Errorf("phase 4 server stopped: %v", runErr)
		}
	})
	command := exec.Command("node", filepath.Join("..", "..", "web", "e2e", "real-change-server-probe.mjs"))
	command.Env = append(os.Environ(), "NODE_NO_WARNINGS=1", "VSK_PHASE3_BASE_URL="+baseURL, "VSK_PHASE3_CONTROLLER_URL="+controller.URL, "VSK_PHASE3_ASSERTION="+assertion, "VSK_PHASE4_PROXY_CERTIFICATE="+certificatePath, "VSK_PHASE4_PROXY_PRIVATE_KEY="+keyPath, "VSK_PHASE4_FULL_LOOP=1")
	if filepath.IsAbs(os.Getenv("VSK_PHASE3_BINARY")) {
		command.Env = append(command.Env, "VSK_PHASE4_CLI_PARITY=1")
	}
	stdout := &boundedProbeOutput{limit: 16 * 1024}
	stderr := &boundedProbeOutput{limit: 512}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		t.Fatalf("phase 4 approved-loop probe failed at %s: %v", phase4ProbeStage(stderr.String()), err)
	}
	if !strings.Contains(stdout.String(), `"status":"pass"`) {
		t.Fatal("phase 4 approved-loop result invalid")
	}
}

func phase4ProbeStage(output string) string {
	const prefix = "PROBE_FAILED:"
	stage := strings.TrimPrefix(sanitizePhase3ProbeError(output), prefix)
	if stage == "" || stage == sanitizePhase3ProbeError(output) {
		return "unreachable"
	}
	return stage
}

func phase4Controller(t *testing.T, databasePath string, bridge *phase4ApprovalBridge, clock func() time.Time, binaryPath, configPath string) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/grant-plan", func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			PlanID string `json:"planId"`
		}
		if request.Method != http.MethodPost || json.NewDecoder(io.LimitReader(request.Body, 1024)).Decode(&input) != nil || !strings.HasPrefix(input.PlanID, "plan-") || grantPhase4PlanAccess(databasePath, input.PlanID, clock()) != nil {
			http.Error(writer, "fixture operation failed", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(writer, `{"status":"succeeded"}`)
	})
	mux.HandleFunc("/approve", func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			PlanID string `json:"planId"`
		}
		if request.Method != http.MethodPost || json.NewDecoder(io.LimitReader(request.Body, 1024)).Decode(&input) != nil || bridge.approve(request.Context(), input.PlanID) != nil {
			http.Error(writer, "fixture operation failed", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(writer, `{"status":"succeeded"}`)
	})
	mux.HandleFunc("/grant-run", func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			RunID string `json:"runId"`
		}
		if request.Method != http.MethodPost || json.NewDecoder(io.LimitReader(request.Body, 1024)).Decode(&input) != nil || !strings.HasPrefix(input.RunID, "run-") {
			http.Error(writer, "fixture operation failed", http.StatusBadRequest)
			return
		}
		formatted := clock().UTC().Format(time.RFC3339Nano)
		if err := updateBrowserIntegrationDatabase(databasePath, `INSERT INTO read_grants(principal_id,capability,resource_kind,resource_id,grant_revision,status,created_at,updated_at) VALUES('principal.remote','run.read','run',?,1,'active',?,?)`, input.RunID, formatted, formatted); err != nil {
			http.Error(writer, "fixture operation failed", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(writer, `{"status":"succeeded"}`)
	})
	mux.HandleFunc("/cli-plan", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || !filepath.IsAbs(binaryPath) || !filepath.IsAbs(configPath) {
			http.Error(writer, "fixture operation failed", http.StatusBadRequest)
			return
		}
		command := exec.Command(binaryPath, "plan", "--config", configPath, "--declaration-id", "declaration-browser", "--revision", "2", "--output", "json")
		stdout := &boundedProbeOutput{limit: 16 * 1024}
		stderr := &boundedProbeOutput{limit: 512}
		command.Stdout, command.Stderr = stdout, stderr
		if err := command.Run(); err != nil || !json.Valid(stdout.Bytes()) {
			http.Error(writer, "fixture operation failed", http.StatusInternalServerError)
			return
		}
		var envelope generated.RunResult
		var presentation generated.PlanPresentation
		if json.Unmarshal(stdout.Bytes(), &envelope) != nil || json.Unmarshal(envelope.Data, &presentation) != nil ||
			!strings.HasPrefix(presentation.Plan.PlanID, "plan-") || grantPhase4PlanAccess(databasePath, presentation.Plan.PlanID, clock()) != nil {
			http.Error(writer, "fixture operation failed", http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(stdout.Bytes())
	})
	return mux
}

func phase4Digest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func seedPhase4BrowserChangeGrants(t *testing.T, databasePath string, now time.Time) {
	t.Helper()
	formatted := now.UTC().Format(time.RFC3339Nano)
	for _, grant := range []struct {
		id, principal, role, action, capability, kind, resource, branch string
	}{
		{"grant-browser-declaration-author", "principal.remote", "author", "author", "declaration.author", "declaration", "declaration-browser", ""},
		{"grant-browser-plan-author", "principal.remote", "author", "author", "plan.author", "declaration", "declaration-browser", ""},
		{"grant-browser-execute", "principal.remote", "infrastructure-admin", "execute", "health.check", "execution-target", "target-browser", "human"},
		{"grant-browser-human-ack", "human.console", "infrastructure-admin", "acknowledge", "plan.acknowledge", "plan-target", "target-browser", "human"},
		{"grant-browser-cancel-declaration-author", "principal.remote", "author", "author", "declaration.author", "declaration", "declaration-browser-cancel", ""},
		{"grant-browser-cancel-plan-author", "principal.remote", "author", "author", "plan.author", "declaration", "declaration-browser-cancel", ""},
		{"grant-browser-cancel-execute", "principal.remote", "infrastructure-admin", "execute", "health.check", "execution-target", "target-browser-cancel", "human"},
		{"grant-browser-cancel-human-ack", "human.console", "infrastructure-admin", "acknowledge", "plan.acknowledge", "plan-target", "target-browser-cancel", "human"},
	} {
		if err := updateBrowserIntegrationDatabase(databasePath, `INSERT INTO effective_authorization_grants(grant_id,principal_id,role_id,action,capability,resource_kind,resource_id,branch,grant_revision,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,1,'active',?,?)`, grant.id, grant.principal, grant.role, grant.action, grant.capability, grant.kind, grant.resource, nullableString(grant.branch), formatted, formatted); err != nil {
			t.Fatal(err)
		}
	}
	for _, grant := range []struct{ principal, revision string }{
		{"principal.remote", "declaration-browser:1"},
		{"principal.remote", "declaration-browser:2"},
		{"principal.remote", "declaration-browser-cancel:1"},
		{"principal.remote", "declaration-browser-cancel:2"},
		{"principal.local", "declaration-browser:2"},
	} {
		if err := updateBrowserIntegrationDatabase(databasePath, `INSERT INTO read_grants(principal_id,capability,resource_kind,resource_id,grant_revision,status,created_at,updated_at) VALUES(?,'declaration.read','declaration',?,1,'active',?,?)`, grant.principal, grant.revision, formatted, formatted); err != nil {
			t.Fatal(err)
		}
	}
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func apiFailureForTest(code string) error { return failure.New(code, "phase4-fixture", false) }

var _ api.AcknowledgementPublisher = (*phase4ApprovalBridge)(nil)
var _ api.AcknowledgementScopeResolver = (*phase4ApprovalBridge)(nil)
var _ adapter.Adapter = (*phase4ResumableAdapter)(nil)
