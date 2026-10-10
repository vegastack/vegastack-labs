//go:build linux

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapters/slack"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type setupAcceptanceTransport struct {
	cards            chan acknowledgement.RequestCard
	incoming         chan []byte
	opens            atomic.Int32
	acknowledgements atomic.Int32
}

func (t *setupAcceptanceTransport) Open(context.Context, []byte) (slack.Socket, error) {
	t.opens.Add(1)
	return &setupAcceptanceSocket{incoming: t.incoming, acknowledgements: &t.acknowledgements}, nil
}
func (t *setupAcceptanceTransport) Publish(ctx context.Context, _ []byte, _ string, _ string, _ string, card acknowledgement.RequestCard) error {
	select {
	case t.cards <- card:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type setupAcceptanceSocket struct {
	incoming         <-chan []byte
	acknowledgements *atomic.Int32
}

func (s *setupAcceptanceSocket) Receive(ctx context.Context) ([]byte, error) {
	select {
	case raw := <-s.incoming:
		return raw, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (s *setupAcceptanceSocket) Acknowledge(context.Context, string) error {
	s.acknowledgements.Add(1)
	return nil
}
func (*setupAcceptanceSocket) Close() error { return nil }

type setupAcceptance struct {
	t                                         *testing.T
	root, configPath, setupPath, databasePath string
	profile                                   generated.ServerProfile
	request                                   generated.LocalSetupRequest
	operations                                *Operations
	transport                                 *setupAcceptanceTransport
}

func newSetupAcceptance(t *testing.T) *setupAcceptance {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("requires non-root isolated test user")
	}
	root := shortServerTempDir(t)
	releaseReview, artifact := setupReleaseFixture(t)
	if err := os.Chmod(releaseReview.request.ReleaseManifestPath, 0600); err != nil {
		t.Fatal(err)
	}
	f := &setupAcceptance{t: t, root: root, configPath: filepath.Join(root, "profile.json"), setupPath: filepath.Join(root, "setup.json"), databasePath: filepath.Join(root, "control.db")}
	uid := int64(os.Geteuid())
	export := filepath.Join(root, "exports")
	if err := os.Mkdir(export, 0700); err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(root, "credentials")
	if err := os.Mkdir(credentials, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"setup-app", "setup-bot", "setup-nonce"} {
		if err := os.WriteFile(filepath.Join(credentials, name), []byte("synthetic-only-"+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CREDENTIALS_DIRECTORY", credentials)
	slackPath := filepath.Join(root, "slack.json")
	writeProtectedJSON(t, slackPath, slackAcknowledgementProfile{WorkspaceID: "T-setup", SlackUserID: "U-setup", HumanID: "human-a", AuthorityID: "authority-setup", ChannelID: "C-setup", ApproveActionID: "approve", RejectActionID: "reject", AppTokenReference: "setup-app", BotTokenReference: "setup-bot", NonceKeyReference: "setup-nonce"})
	f.profile = generated.ServerProfile{Schema: generated.SchemaIDServerProfile, SchemaVersion: "1.3.0", SocketPath: filepath.Join(root, "control.sock"), SocketOwnerUID: uid, SocketMode: "0600", ShutdownGraceSeconds: 5, InventoryExportRoot: export, PrincipalBindings: []generated.LocalPrincipalBinding{{UID: uid, PrincipalID: "human-a"}}, AcknowledgementAdapterConfigPath: slackPath}
	writeProtectedJSON(t, f.configPath, f.profile)
	f.request = validLocalSetupRequest(time.Now())
	f.request.ServiceUID = uid
	f.request.InitialAdministratorUID = uid
	f.request.DatabasePath = f.databasePath
	profileRaw, _ := os.ReadFile(f.configPath)
	f.request.ProfileSHA256 = setupSHA256(profileRaw)
	f.request.ReleaseManifestPath = releaseReview.request.ReleaseManifestPath
	f.request.ReleaseManifestDigest = releaseReview.request.ReleaseManifestDigest
	f.request.ReleasePolicyPath = releaseReview.request.ReleasePolicyPath
	f.request.ReleasePolicyDigest = releaseReview.request.ReleasePolicyDigest
	f.request.InitialReadGrants = append(f.request.InitialReadGrants, generated.LocalSetupReadGrant{Schema: generated.SchemaIDLocalSetupReadGrant, SchemaVersion: "1.0.0", Capability: "control.health.read", ResourceKind: "control", ResourceID: "control"})
	f.request.InitialEffectiveGrants = append(f.request.InitialEffectiveGrants, generated.LocalSetupEffectiveGrant{Schema: generated.SchemaIDLocalSetupEffectiveGrant, SchemaVersion: "1.0.0", GrantID: "grant-declaration", RoleID: "infrastructure-admin", Action: "author", Capability: "declaration.author", ResourceKind: "declaration", ResourceID: "gate-profile-initial", Branch: "none"})
	writeProtectedJSON(t, f.setupPath, f.request)
	f.transport = &setupAcceptanceTransport{cards: make(chan acknowledgement.RequestCard, 4), incoming: make(chan []byte, 8)}
	var ids atomic.Int64
	f.operations = NewOperations(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "build-123"}, func() (string, error) { return "setup-request-" + fmt.Sprint(ids.Add(1)), nil })
	f.operations.databasePath = f.databasePath
	f.operations.platformProbe = fixedPlatformProbe{platform: testSupportedPlatform()}
	f.operations.setupHostIdentity = func(context.Context) (string, error) { return "sha256:" + strings.Repeat("a", 64), nil }
	f.operations.setupExecutable = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(artifact)), nil }
	f.operations.acknowledgementTransport = f.transport
	return f
}
func (f *setupAcceptance) start(setup bool) (context.CancelFunc, <-chan error) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		if setup {
			done <- f.operations.RunSetup(ctx, f.configPath, f.setupPath)
		} else {
			done <- f.operations.Run(ctx, f.configPath)
		}
	}()
	f.t.Cleanup(cancel)
	return cancel, done
}
func (f *setupAcceptance) card(done <-chan error) acknowledgement.RequestCard {
	f.t.Helper()
	select {
	case card := <-f.transport.cards:
		return card
	case err := <-done:
		f.t.Fatalf("setup ended before approval: %v", err)
	case <-time.After(8 * time.Second):
		f.t.Fatal("setup card unavailable")
	}
	return acknowledgement.RequestCard{}
}
func (f *setupAcceptance) send(card acknowledgement.RequestCard, change func(map[string]any)) {
	binding := map[string]any{"planId": card.Request.PlanID, "planDigest": card.Request.PlanDigest, "targetDigest": card.Request.TargetDigest, "reasonDigest": card.Request.ReasonDigest, "nonce": card.Nonce, "stateRevision": card.Request.StateRevision, "recoveryEpoch": card.Request.RecoveryEpoch, "expiresAt": card.Request.ExpiresAt}
	if change != nil {
		change(binding)
	}
	value, _ := json.Marshal(binding)
	// Normal Slack metadata from the documented block_actions / Socket Mode envelopes.
	envelope := map[string]any{"envelope_id": "setup-envelope", "type": "interactive", "accepts_response_payload": true, "payload": map[string]any{
		"type": "block_actions", "api_app_id": "A-setup", "trigger_id": "synthetic-trigger", "response_url": "https://example.invalid/synthetic", "is_enterprise_install": false,
		"team": map[string]string{"id": "T-setup", "domain": "synthetic"}, "user": map[string]string{"id": "U-setup", "username": "synthetic", "team_id": "T-setup"},
		"container": map[string]any{"type": "message", "message_ts": "1.0", "channel_id": "C-setup", "is_ephemeral": false}, "channel": map[string]string{"id": "C-setup", "name": "setup"},
		"message": map[string]any{"type": "message", "ts": "1.0", "text": card.ReviewText},
		"actions": []map[string]string{{"action_id": "approve", "block_id": "setup-actions", "type": "button", "action_ts": "1.0", "value": string(value)}}}}
	raw, _ := json.Marshal(envelope)
	f.transport.incoming <- raw
}
func (f *setupAcceptance) call(method, path string, input any) (int, []byte, error) {
	var raw []byte
	if input != nil {
		raw, _ = json.Marshal(input)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", f.profile.SocketPath)
	}}
	defer transport.CloseIdleConnections()
	request, _ := http.NewRequest(method, "http://local"+path, bytes.NewReader(raw))
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return response.StatusCode, body, err
}
func (f *setupAcceptance) ready(done <-chan error, want int) {
	f.t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			f.t.Fatalf("server startup failed: %v", err)
		default:
		}
		code, body, err := f.call("GET", "/api/v1/database/status", nil)
		if err == nil {
			if code != want {
				f.t.Fatalf("status %d want%d: %s", code, want, body)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.t.Fatal("local API did not start")
}
func (f *setupAcceptance) stop(cancel context.CancelFunc, done <-chan error) {
	f.t.Helper()
	cancel()
	select {
	case err := <-done:
		if stable, ok := failure.As(err); err != nil && (!ok || stable.Code != generated.ErrorCodeInterrupted) {
			f.t.Fatalf("server stop: %v", err)
		}
	case <-time.After(8 * time.Second):
		f.t.Fatal("server stop timeout")
	}
}

func TestLocalSetupFirstStartAndRestart(t *testing.T) {
	f := newSetupAcceptance(t)
	cancel, done := f.start(true)
	card := f.card(done)
	if _, err := os.Stat(f.databasePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("database created before approval")
	}
	if _, err := os.Stat(f.profile.SocketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ordinary listener before approval")
	}
	if !strings.Contains(card.ReviewText, "gate-profile-initial") || strings.Contains(card.ReviewText, f.request.RequestNonce) || strings.Contains(card.ReviewText, card.Nonce) {
		t.Fatal("review missing scope or leaking nonce")
	}
	for _, field := range []string{`"externalScopeId": "T-setup"`, `"externalSubjectId": "U-setup"`, `"deliveryTargetId": "C-setup"`, `"humanId": "human-a"`, `"authorityId": "authority-setup"`, `"method": "` + identity.SlackSocketModeMethod + `"`, `"profileDigest": "sha256:`} {
		if !strings.Contains(card.ReviewText, field) {
			t.Fatalf("review missing complete mapping: %s", field)
		}
	}
	f.send(card, nil)
	f.ready(done, http.StatusOK)
	scope := store.GateAppliedProfile{ProfileID: "profile-initial", ProfileVersion: "1.0.0", PolicyID: "policy-initial", PolicyVersion: "1.0.0", Capabilities: []string{"host.discovery"}}
	digest, err := store.ProfileScopeDigest(scope)
	if err != nil {
		t.Fatal(err)
	}
	request := generated.GateProfileDraftRequest{Schema: generated.SchemaIDGateProfileDraftRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 0, RecoveryEpoch: 0, TargetDigest: digest, IdempotencyKey: "setup-profile-draft", BindingID: "initial", ProfileID: scope.ProfileID, ProfileVersion: scope.ProfileVersion, PolicyID: scope.PolicyID, PolicyVersion: scope.PolicyVersion, Capabilities: scope.Capabilities}
	_, statusBody, statusErr := f.call("GET", "/api/v1/database/status", nil)
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	var status struct {
		StateRevision int64 `json:"stateRevision"`
		RecoveryEpoch int64 `json:"recoveryEpoch"`
	}
	if err := json.Unmarshal(statusBody, &status); err != nil {
		t.Fatal(err)
	}
	request.ExpectedStateRevision = status.StateRevision
	request.RecoveryEpoch = status.RecoveryEpoch
	rawRequest, _ := json.Marshal(request)
	if err := generated.ValidateContractJSON(generated.SchemaIDGateProfileDraftRequest, rawRequest, generated.ContractExact); err != nil {
		t.Fatal(err)
	}
	code, body, err := f.call("POST", "/api/v1/gates/profile-drafts", request)
	if err != nil || code < 200 || code >= 300 {
		t.Fatalf("imported author grants unusable: %d %s %v", code, body, err)
	}
	var submitted struct {
		Data generated.GateProfileDraftSubmission `json:"data"`
	}
	if err := json.Unmarshal(body, &submitted); err != nil {
		t.Fatal(err)
	}
	// Profile-draft authoring is an explicitly declared capability. Test a
	// different declaration.author target rather than an unscoped binding ID.
	undeclared := generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: "gate-profile-unapproved", DeclarationType: "gate.profile", ExpectedRevision: 1, ExpectedStateRevision: submitted.Data.StateRevision, RecoveryEpoch: request.RecoveryEpoch, ReasonDigest: digest, Extensions: []generated.ContractExtension{}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "unapproved", OperationType: "gate.profile.activate", AdapterID: "core.gate", TargetID: "profile-unapproved", InputDigest: digest, ArtifactDigest: digest, Idempotent: true}}}
	code, _, _ = f.call("POST", "/api/v1/declarations/gate-profile-unapproved/revisions", undeclared)
	if code != http.StatusForbidden {
		t.Fatalf("undeclared scope status %d", code)
	}
	f.stop(cancel, done)
	if err := f.operations.RunSetup(context.Background(), f.configPath, f.setupPath); err == nil {
		t.Fatal("committed setup replayed")
	}
	receipt, err := os.ReadFile(f.setupPath + ".approval.json")
	if err != nil || !bytes.Contains(receipt, []byte("gate-profile-initial")) || bytes.Contains(receipt, []byte(f.request.RequestNonce)) {
		t.Fatal("durable review receipt missing or leaks nonce")
	}
	if err = os.Remove(f.setupPath); err != nil {
		t.Fatal(err)
	}
	cancel, done = f.start(false)
	f.ready(done, http.StatusOK)
	f.stop(cancel, done)
	// A different explicitly mapped OS human gets no bootstrap authority.
	f.profile.PrincipalBindings[0].PrincipalID = "human-other"
	writeProtectedJSON(t, f.configPath, f.profile)
	cancel, done = f.start(false)
	f.ready(done, http.StatusForbidden)
	f.stop(cancel, done)
}

func TestLocalSetupProtectedFixture(t *testing.T) {
	f := newSetupAcceptance(t)
	uid := uint32(os.Geteuid())
	for stage, path := range map[string]string{"setup": f.setupPath, "profile": f.configPath, "slack": f.profile.AcknowledgementAdapterConfigPath, "manifest": f.request.ReleaseManifestPath, "policy": f.request.ReleasePolicyPath} {
		parentInfo, parentErr := os.Stat(filepath.Dir(path))
		if parentErr != nil {
			t.Fatal(parentErr)
		}
		t.Logf("%s parent mode=%o", stage, parentInfo.Mode().Perm())
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s stat: %v", stage, err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode %o", stage, info.Mode().Perm())
		}
		if _, err = readLocalSetupProtected(context.Background(), path, uid, 1<<20); err != nil {
			t.Fatalf("%s protected read: %v", stage, err)
		}
	}
	review, err := loadLocalSetup(context.Background(), f.setupPath, f.configPath, uid)
	if err != nil {
		t.Fatalf("load frozen setup: %v", err)
	}
	if err = verifyLocalSetupRelease(context.Background(), review, "build-123", testSupportedPlatform(), f.operations.setupExecutable); err != nil {
		t.Fatalf("release binding: %v", err)
	}
	if review.request.HostIdentityDigest != f.request.HostIdentityDigest || review.request.DatabasePath != f.databasePath {
		t.Fatal("frozen identity mismatch")
	}
}

func TestLocalSetupPreflightDenialsPreserveData(t *testing.T) {
	for _, name := range []string{"existing", "empty", "symlink", "journal", "lock", "setup-mode", "setup-symlink", "setup-parent", "profile-changed", "host", "expired", "credentials-parent", "app-missing", "bot-missing"} {
		t.Run(name, func(t *testing.T) {
			f := newSetupAcceptance(t)
			original := []byte("existing-unrelated-data")
			marker := filepath.Join(f.root, "preserve.txt")
			if err := os.WriteFile(marker, original, 0600); err != nil {
				t.Fatal(err)
			}
			existing := false
			switch name {
			case "existing":
				os.WriteFile(f.databasePath, original, 0600)
				existing = true
			case "empty":
				os.WriteFile(f.databasePath, nil, 0600)
				existing = true
			case "symlink":
				os.Symlink(marker, f.databasePath)
				existing = true
			case "journal":
				os.WriteFile(f.databasePath+"-journal", original, 0600)
			case "lock":
				os.WriteFile(f.databasePath+".lock", original, 0600)
			case "setup-mode":
				os.Chmod(f.setupPath, 0644)
			case "setup-symlink":
				old := f.setupPath
				f.setupPath = filepath.Join(f.root, "linked.json")
				os.Symlink(old, f.setupPath)
			case "setup-parent":
				os.Chmod(f.root, 0755)
			case "profile-changed":
				os.WriteFile(f.configPath, []byte("{}"), 0600)
			case "host":
				f.operations.setupHostIdentity = func(context.Context) (string, error) { return "sha256:" + strings.Repeat("f", 64), nil }
			case "expired":
				f.request.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
				writeProtectedJSON(t, f.setupPath, f.request)
			case "credentials-parent":
				os.Chmod(os.Getenv("CREDENTIALS_DIRECTORY"), 0755)
			case "app-missing":
				os.Remove(filepath.Join(os.Getenv("CREDENTIALS_DIRECTORY"), "setup-app"))
			case "bot-missing":
				os.Remove(filepath.Join(os.Getenv("CREDENTIALS_DIRECTORY"), "setup-bot"))
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			started := time.Now()
			err := f.operations.RunSetup(ctx, f.configPath, f.setupPath)
			if err == nil {
				t.Fatal("invalid setup succeeded")
			}
			if time.Since(started) > time.Second {
				t.Fatal("fatal preflight/credential failure waited for approval timeout")
			}
			if !existing {
				if _, err := os.Lstat(f.databasePath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("denied setup created database")
				}
			}
			after, _ := os.ReadFile(marker)
			if !bytes.Equal(after, original) {
				t.Fatal("unrelated data changed")
			}
			if name == "existing" {
				after, _ = os.ReadFile(f.databasePath)
				if !bytes.Equal(after, original) {
					t.Fatal("existing database changed")
				}
			}
			if name == "empty" {
				st, _ := os.Stat(f.databasePath)
				if st.Size() != 0 {
					t.Fatal("empty database initialized")
				}
			}
		})
	}
}
func TestLocalSetupChangedIntentPreservesApproval(t *testing.T) {
	f := newSetupAcceptance(t)
	cancel, done := f.start(true)
	defer cancel()
	card := f.card(done)
	original, _ := os.ReadFile(f.configPath)
	if err := os.WriteFile(f.configPath, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	f.send(card, nil)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("changed intent initialized")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("changed intent hung")
	}
	if _, err := os.Stat(f.databasePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("changed intent created database")
	}
	receipt, err := os.ReadFile(f.setupPath + ".approval.json")
	if err != nil || !bytes.Contains(receipt, []byte(card.Request.PlanDigest)) {
		t.Fatal("accepted intent was lost")
	}
	if err = os.WriteFile(f.configPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err = f.operations.RunSetup(context.Background(), f.configPath, f.setupPath); err == nil {
		t.Fatal("receipt became replay authority")
	}
}
func TestLocalSetupApprovalTransportDenials(t *testing.T) {
	for _, name := range []string{"workspace", "user", "action", "nonce", "digest"} {
		t.Run(name, func(t *testing.T) {
			f := newSetupAcceptance(t)
			cancel, done := f.start(true)
			card := f.card(done)
			binding := map[string]any{"planId": card.Request.PlanID, "planDigest": card.Request.PlanDigest, "targetDigest": card.Request.TargetDigest, "reasonDigest": card.Request.ReasonDigest, "nonce": card.Nonce, "stateRevision": 0, "recoveryEpoch": 0, "expiresAt": card.Request.ExpiresAt}
			workspace, user, action := "T-setup", "U-setup", "approve"
			switch name {
			case "workspace":
				workspace = "T-other"
			case "user":
				user = "U-other"
			case "action":
				action = "other"
			case "nonce":
				binding["nonce"] = "unapproved"
			case "digest":
				binding["planDigest"] = "sha256:" + strings.Repeat("f", 64)
			}
			value, _ := json.Marshal(binding)
			raw, _ := json.Marshal(map[string]any{"envelope_id": "denied-envelope", "type": "interactive", "payload": map[string]any{"type": "block_actions", "team": map[string]string{"id": workspace}, "user": map[string]string{"id": user}, "actions": []map[string]string{{"action_id": action, "value": string(value)}}}})
			f.transport.incoming <- raw
			time.Sleep(60 * time.Millisecond)
			if _, err := os.Stat(f.databasePath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid provider interaction created authority")
			}
			f.send(card, nil)
			f.ready(done, http.StatusOK)
			f.stop(cancel, done)
		})
	}
}
func TestLocalSetupInitializationInterruption(t *testing.T) {
	for _, stage := range []string{"before-create", "after-commit"} {
		t.Run(stage, func(t *testing.T) {
			f := newSetupAcceptance(t)
			f.operations.openStore = func(ctx context.Context, c store.Config) (*store.Store, error) {
				if c.Mode == store.InitializeNew {
					if stage == "before-create" {
						return nil, errors.New("synthetic interruption before create")
					}
					authority, err := store.Open(ctx, c)
					if err != nil {
						return nil, err
					}
					if err = authority.Close(); err != nil {
						return nil, err
					}
					return nil, errors.New("synthetic interruption after durable commit")
				}
				return store.Open(ctx, c)
			}
			cancel, done := f.start(true)
			defer cancel()
			card := f.card(done)
			f.send(card, nil)
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("fault did not interrupt")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("fault not reached")
			}
			if _, err := os.Stat(f.setupPath + ".approval.json"); err != nil {
				t.Fatal("accepted approval lost")
			}
			f.operations.openStore = store.Open
			if stage == "after-commit" {
				cancel, done = f.start(false)
				f.ready(done, http.StatusOK)
				f.stop(cancel, done)
			} else {
				if _, err := os.Stat(f.databasePath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("precreate interruption wrote database")
				}
				if err := f.operations.RunSetup(context.Background(), f.configPath, f.setupPath); err == nil {
					t.Fatal("interrupted receipt replayed")
				}
			}
		})
	}
}

func TestLocalSetupReceiptFailureCannotAcknowledge(t *testing.T) {
	f := newSetupAcceptance(t)
	cancel, done := f.start(true)
	defer cancel()
	card := f.card(done)
	receipt := f.setupPath + ".approval.json"
	original := []byte("preserved-competing-receipt")
	if err := os.WriteFile(receipt, original, 0600); err != nil {
		t.Fatal(err)
	}
	f.send(card, nil)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("receipt failure accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receipt failure hung")
	}
	if f.transport.acknowledgements.Load() != 0 {
		t.Fatal("failed durable receipt acknowledged")
	}
	after, _ := os.ReadFile(receipt)
	if !bytes.Equal(after, original) {
		t.Fatal("competing receipt overwritten")
	}
	if _, err := os.Stat(f.databasePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("receipt failure created database")
	}
}

func TestLocalSetupConcurrentOneWinner(t *testing.T) {
	first := newSetupAcceptance(t)
	second := *first
	ops := *first.operations
	second.operations = &ops
	second.transport = &setupAcceptanceTransport{cards: make(chan acknowledgement.RequestCard, 4), incoming: make(chan []byte, 8)}
	second.operations.acknowledgementTransport = second.transport
	cancel1, done1 := first.start(true)
	defer cancel1()
	cancel2, done2 := second.start(true)
	defer cancel2()
	card1, card2 := first.card(done1), second.card(done2)
	if card1.Nonce == card2.Nonce {
		t.Fatal("concurrent attempts reused challenge")
	}
	first.send(card1, nil)
	second.send(card2, nil)
	select {
	case err := <-done1:
		if err == nil {
			t.Fatal("loser unexpectedly succeeded")
		}
		second.ready(done2, http.StatusOK)
		second.stop(cancel2, done2)
	case err := <-done2:
		if err == nil {
			t.Fatal("loser unexpectedly succeeded")
		}
		first.ready(done1, http.StatusOK)
		first.stop(cancel1, done1)
	case <-time.After(8 * time.Second):
		t.Fatal("concurrent initialization has no bounded loser")
	}
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: first.databasePath, Mode: store.OpenExisting, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "build-123"})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	digest, err := authority.ReadInitialSetupDigest(context.Background())
	if err != nil || digest != card1.Request.PlanDigest {
		t.Fatal("winning authority missing exact setup digest", err)
	}
}
