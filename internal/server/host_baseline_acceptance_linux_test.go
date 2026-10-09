//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	transport "github.com/vegastack/vegastack-labs/internal/adapter/hostaction"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
	"golang.org/x/crypto/ssh"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Real persisted API/plan/Slack/SSH/receipt path; only target OS reads and the
// prequalified signer credential are synthetic. This proves no native qualification.
func TestHostBaselineAcceptance(t *testing.T) {
	for _, mode := range []string{"success", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			state := &baselineAcceptanceRuntime{mode: mode}
			hostActionAcceptance(t, "success", hostActionAcceptanceHooks{EnrollmentOnly: true, Peer: func(t *testing.T, k ssh.Signer, s ActionSigner, _ *atomic.Int32, dir string) int {
				return baselineAcceptancePeer(t, k, s, dir, state)
			}, Enrollment: func(t *testing.T, f hostActionEnrollmentFixture) adapter.CredentialResolver {
				runBaselineAcceptance(t, f, state)
				return hostActionAcceptanceCredential{key: f.Key}
			}})
		})
	}
}

type baselineAcceptanceRenderer struct{}

func (baselineAcceptanceRenderer) RenderPolicy(_ context.Context, in generated.DebianBaselineInput) (string, error) {
	return debianbaseline.PolicyDigest(in), nil
}
func baselineAcceptanceRequest(t *testing.T, f hostActionEnrollmentFixture) generated.HostActionRequest {
	lock := accessAcceptanceInput(t, f).ProfileLock
	lock.Packages = []generated.AccessPackage{{Schema: generated.SchemaIDAccessPackage, SchemaVersion: "1.0.0", Name: "systemd", Version: "synthetic-test"}}
	in := generated.DebianBaselineInput{Schema: generated.SchemaIDDebianBaselineInput, SchemaVersion: "1.0.0", HostID: "synthetic-host", HostIdentityDigest: f.DestinationIdentity, ProfileID: "test-profile", ProfileLock: lock, ProfileLockDigest: hostaction.Digest(lock), RoleID: "host", ActionVersion: "1.0.0", AutomationUID: 1001, ControlIDs: []string{"linux.time-sync"}, RecoverySourcePrefixes: []string{"127.0.0.1/32"}, UpdateOwner: "operator", TimeOwner: "systemd-timesyncd", AuditPaths: []string{}, AppArmorProfiles: []generated.BaselineApparmorProfile{}, AIDE: generated.BaselineAidePolicy{Schema: generated.SchemaIDBaselineAidePolicy, SchemaVersion: "1.0.0", ScopePaths: []string{}, ScopeDigest: hostaction.Digest([]string{})}, Resources: []generated.BaselineResourceLimit{}, KernelSettings: []generated.BaselineKernelSetting{}, Volumes: []generated.HostVolumeBinding{}}
	in.RenderedPolicyDigest = debianbaseline.PolicyDigest(in)
	raw, _ := json.Marshal(in)
	if _, e := debianbaseline.DecodeInput(raw); e != nil {
		t.Fatal(e)
	}
	current, e := store.NewPlanRepository(f.Authority).CurrentRevision(f.Context)
	if e != nil {
		t.Fatal(e)
	}
	return generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", ActionID: "debian.baseline.collect", ActionVersion: "1.0.0", ActionInput: string(raw), ActionInputDigest: hostaction.BytesDigest(raw), HostID: "synthetic-host", TargetRevision: 1, TargetDigest: f.TargetDigest, AutomationPrincipalID: "automation-a", CallerUID: 1001, CredentialReferenceID: "action-key", CredentialMaterialVersion: "version-a", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: f.TargetDigest, HostIdentityDigest: f.DestinationIdentity}, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: "baseline-a"}
}

type baselineAcceptanceRuntime struct {
	mode  string
	calls atomic.Int32
}

func (*baselineAcceptanceRuntime) Inspect(_ context.Context, b generated.HostActionBundle, in generated.DebianBaselineInput) error {
	if b.HostID != in.HostID {
		return fmt.Errorf("host mismatch")
	}
	return nil
}
func (*baselineAcceptanceRuntime) Apply(context.Context, generated.HostActionBundle, generated.DebianBaselineInput) (debianbaseline.Result, error) {
	return debianbaseline.Result{}, fmt.Errorf("mutations forbidden in collect fixture")
}
func (r *baselineAcceptanceRuntime) Collect(ctx context.Context, _ generated.HostActionBundle, in generated.DebianBaselineInput) (debianbaseline.Result, error) {
	r.calls.Add(1)
	m, e := debianbaseline.Collect(ctx, in, r)
	return debianbaseline.Result{Measurements: m}, e
}
func (r *baselineAcceptanceRuntime) Read(_ context.Context, q debianbaseline.ReadRequest) ([]byte, error) {
	if r.mode == "unavailable" {
		return nil, fmt.Errorf("synthetic OS unavailable")
	}
	if q.Operation != debianbaseline.ReadTime {
		return nil, fmt.Errorf("unexpected OS read")
	}
	return []byte("NTPSynchronized=yes\nOffsetSeconds=0.1\n"), nil
}
func runBaselineAcceptance(t *testing.T, f hostActionEnrollmentFixture, state *baselineAcceptanceRuntime) {
	t.Helper()
	ctx := f.Context
	exec := func(query string, args ...any) {
		t.Helper()
		if _, e := f.DB.ExecContext(ctx, query, args...); e != nil {
			t.Fatal(e)
		}
	}
	d := hostaction.Digest("synthetic-active-key")
	exec(`INSERT INTO credential_reference_versions VALUES('access-active','action-key','host-action','host-action-ssh','synthetic-host','native-systemd','version-a',?,'active',1,0,?,?,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, d, time.Now().UTC().Format(time.RFC3339), []byte(`["host-action"]`), d)
	exec(`INSERT INTO effective_authorization_principals VALUES('automation-a','agent','active',1,'now','now')`)
	exec(`INSERT INTO effective_authorization_grants VALUES('automation-action','automation-a','infrastructure-admin','execute','host.action.execute','execution-target','synthetic-host','human',1,'active','now','now')`)
	grant := func(id, action, cap, kind, target string, branch any) {
		exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?,?,?,1,'active','now','now')`, id, action, cap, kind, target, branch)
	}
	grant("access-prepare", "author", "host.action.prepare", "host", "synthetic-host", nil)
	request := baselineAcceptanceRequest(t, f)
	declarationID := hostaction.DraftID(request)
	grant("access-declaration", "author", "declaration.author", "declaration", declarationID, nil)
	hosts := store.NewHostActionRepository(f.Authority)
	credentials := store.NewCredentialRepository(f.Authority)
	if e := api.RegisterHostActionOperations(f.App, api.HostActionOperations{Hosts: hosts, Declarations: f.Declarations, Credentials: credentials, BaselineRenderer: baselineAcceptanceRenderer{}, Results: f.Results}); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(request)
	httpRequest := httptest.NewRequest("POST", "/api/v1/host-actions/draft", bytes.NewReader(raw)).WithContext(ctx)
	httpRequest.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.App.ServeHTTP(w, httpRequest)
	if w.Code != 200 && w.Code != 201 {
		t.Fatalf("draft HTTP%d: %s", w.Code, w.Body.String())
	}
	var envelope struct {
		Data generated.HostActionSubmission `json:"data"`
	}
	if json.Unmarshal(w.Body.Bytes(), &envelope) != nil || envelope.Data.DeclarationID != declarationID {
		t.Fatal("wrong draft response")
	}
	revisions := store.NewPlanRepository(f.Authority)
	observations, e := planengine.NewStateObservationReader(revisions)
	if e != nil {
		t.Fatal(e)
	}
	plans, e := planengine.NewService(planengine.Config{HostActions: hosts, HostActionCredentials: credentials, Repository: revisions, Observations: observations, Clock: time.Now, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if e != nil {
		t.Fatal(e)
	}
	declaration, e := f.Declarations.Get(ctx, declarationID, 1)
	if e != nil {
		t.Fatal(e)
	}
	current, e := revisions.CurrentRevision(ctx)
	if e != nil {
		t.Fatal(e)
	}
	fingerprint, e := observations.CurrentFingerprint(ctx, declarationID, declaration.Operations)
	if e != nil {
		t.Fatal(e)
	}
	created, e := plans.Create(ctx, planengine.AuthorScope{PrincipalID: "operator-a", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "access-test"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: declarationID, DeclarationRevision: 1, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, ObservationFingerprint: fingerprint, IdempotencyKey: "access-plan", Extensions: declaration.Extensions})
	if e != nil {
		t.Fatal(e)
	}
	p := created.Plan
	grant("access-execute", "execute", "host.action.execute", "execution-target", "synthetic-host", "human")
	grant("access-ack", "acknowledge", "plan.acknowledge", "plan-target", "synthetic-host", "human")
	policy := store.NewEffectiveAuthorizationRepository(f.Authority)
	ack, e := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(f.Authority), Plans: lifecycleAcceptancePlanReader{plans}, Authorizer: authorization.NewEvaluator(policy), Clock: time.Now})
	if e != nil {
		t.Fatal(e)
	}
	human := identity.Principal{ID: "operator-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	card, e := ack.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: "access-nonce"}, p.PlanID)
	if e != nil {
		t.Fatal(e)
	}
	approved := hostActionAcceptanceSlackApproval(t, ack, card)
	live, e := NewHostActionAuthority(hosts, f.Signer, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	composition := hostAccessComposition{store: f.Authority, hosts: hosts, allowed: []string{f.DestinationIdentity}}
	recorder := baselineAcceptanceRecorder{composition, t}
	implementation, e := transport.NewWithAccess(hostActionTargets{repository: hosts, allowed: []string{f.DestinationIdentity}}, &HostActionBundleIssuer{Repository: hosts, Signer: f.Signer, Clock: time.Now}, live, composition, debianaccess.NewLocalProbe(debianaccess.LocalProbeRuntime{}), recorder)
	if e != nil {
		t.Fatal(e)
	}
	registry := adapter.NewRegistry()
	if e = registry.Register(hostaction.AdapterID, implementation); e != nil {
		t.Fatal(e)
	}
	if e = registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: "host-action", ProfileID: "synthetic-profile", CapabilityID: "synthetic-capability", Enabled: true}, hostActionAcceptanceCredential{key: f.Key}); e != nil {
		t.Fatal(e)
	}
	engine, e := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(f.Authority), Plans: plans, Admission: runengine.NewAdmissionGate(ack, time.Now), Adapters: registry, SecretGate: hostActionGate{targets: hosts, allowed: []string{f.DestinationIdentity}}, CredentialStep: &runengine.CredentialStep{Bindings: credentials, Resolvers: registry, Profiles: hostActionAcceptanceProfile{}, Plans: plans, Clock: time.Now}, Clock: time.Now})
	if e != nil {
		t.Fatal(e)
	}
	branch := "human"
	decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "access-decision", PrincipalID: human.ID, Action: "execute", TargetID: "synthetic-host", Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, PlanDigest: p.PlanDigest, DecidedAt: time.Now().UTC().Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	applied, err := engine.Submit(ctx, runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, IdempotencyKey: "run-access", Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: audit.Attribution{AuthenticatedPrincipalID: human.ID, AuthenticatedPrincipalMethod: human.Method, ResponsibleHumanPrincipalID: &human.ID}})

	if err != nil || applied.Status != "succeeded" || state.calls.Load() != 1 {
		t.Fatalf("baseline did not collect once: run=%+v err=%v calls=%d", applied, err, state.calls.Load())
	}
	rows, e := store.NewGateRepository(f.Authority).ReadHostControlResults(ctx, "synthetic-host")
	if e != nil || len(rows) != 1 {
		t.Fatalf("missing current receipt: rows=%+v err=%v", rows, e)
	}
	var stored generated.AccessMeasurement
	var measurement []byte
	if e = f.DB.QueryRow(`SELECT measurement_bytes FROM host_control_results`).Scan(&measurement); e != nil {
		t.Fatal(e)
	}
	if json.Unmarshal(measurement, &stored) != nil || stored.Baseline == nil || stored.Baseline.NativeQualificationDigest != "" {
		t.Fatal("invalid qualification projection")
	}
	expected := "passed"
	if state.mode == "unavailable" {
		expected = "partial"
	}
	if stored.Status != expected {
		t.Fatalf("status=%s want%s", stored.Status, expected)
	}
	var n int
	if e = f.DB.QueryRow(`SELECT count(*) FROM gate_applied_evidence`).Scan(&n); e != nil || n != 0 {
		t.Fatal("software promoted admission", n, e)
	}
}
func baselineAcceptancePeer(t *testing.T, key ssh.Signer, signer ActionSigner, directory string, state *baselineAcceptanceRuntime) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	receiptsPath := filepath.Join(directory, "receipts")
	if err = os.Mkdir(receiptsPath, 0700); err != nil {
		t.Fatal(err)
	}
	receipts, err := hostaction.OpenReceipts(receiptsPath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receipts.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
				cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
					if !bytes.Equal(k.Marshal(), key.PublicKey().Marshal()) {
						return nil, fmt.Errorf("wrong synthetic credential")
					}
					return nil, nil
				}}
				cfg.AddHostKey(key)
				server, channels, requests, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					if channel.ChannelType() != "session" {
						_ = channel.Reject(ssh.UnknownChannelType, "denied")
						continue
					}
					ch, reqs, err := channel.Accept()
					if err != nil {
						return
					}
					defer ch.Close()
					for req := range reqs {
						var command struct{ Command string }
						if req.Type != "exec" || ssh.Unmarshal(req.Payload, &command) != nil || command.Command != "/usr/bin/sudo -n -- /usr/local/bin/vsk-labs host-action-once" {
							_ = req.Reply(false, nil)
							continue
						}
						_ = req.Reply(true, nil)
						policy := hostaction.Policy{HostID: "synthetic-host", HostIdentityDigest: hostadoption.IdentityDigest("product-serial", "synthetic-serial"), CallerUID: 1001, KeyID: signer.KeyID(), PublicKey: signer.PublicKey()}
						err = hostaction.RunOnce(context.Background(), ch, ch, policy, receipts, debianbaseline.NewDispatcher(state), time.Now, rand.Reader)
						if err != nil {
							t.Logf("baseline peer protocol: %v", err)
						}
						code := uint32(0)
						if err != nil {
							code = 1
						}
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
						return
					}
				}
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

type baselineAcceptanceRecorder struct {
	actual hostAccessComposition
	t      *testing.T
}

func (r baselineAcceptanceRecorder) RecordVerifiedControlResults(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, e adapter.Effect, result generated.HostActionResult) error {
	err := r.actual.RecordVerifiedControlResults(ctx, op, b, e, result)
	if err != nil {
		r.t.Logf("baseline recorder: %v result=%+v", err, result)
	}
	return err
}
