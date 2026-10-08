//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	collector "github.com/vegastack/vegastack-labs/internal/adapter/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
	"golang.org/x/crypto/ssh"
)

// This Linux integration test uses a real temporary database and loopback SSH.
// Credential/profile qualification and the Slack delivery adapter are fixtures;
// no OS commands, native credential service, or actual host is exercised.
func TestHostDiscoveryAcceptanceDatabaseAPIApprovalAndSSH(t *testing.T) {
	discoveryAcceptanceFlow(t, true, "13.6", "13")
}
func TestHostDiscoveryAcceptanceUnqualifiedRecovery(t *testing.T) {
	discoveryAcceptanceFlow(t, false, "13.6", "13")
}
func TestHostDiscoveryAcceptanceConflictingVersions(t *testing.T) {
	for _, expected := range []string{"13", "12.9"} {
		t.Run(expected, func(t *testing.T) { discoveryAcceptanceFlow(t, true, "12.9", expected) })
	}
}
func discoveryAcceptanceFlow(t *testing.T, qualified bool, pointVersion, expectedVersion string) {
	ctx := context.Background()
	captureStart := time.Now().UTC().Truncate(time.Second)
	fixtureNow := captureStart
	clock := func() time.Time { return fixtureNow }
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.db")
	authority, err := store.Open(ctx, store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO effective_authorization_principals VALUES('operator-a','human','active',1,'now','now')`)
	grant := func(capability, kind, id, action string) {
		t.Helper()
		exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','infrastructure-admin',?,?,?, ?,NULL,1,'active','now','now')`, "grant-"+hostdiscovery.Digest([]string{capability, id})[7:25], action, capability, kind, id)
	}
	for _, c := range []string{"host.discovery.collect", "host.discovery.read"} {
		grant(c, "host-discovery-target", "candidate-a", "read")
	}
	grant("host.discovery.target.prepare", "host-discovery-target", "candidate-a", "author")
	exec(`INSERT INTO read_principals VALUES('operator-a','active',1,'now','now')`)
	exec(`INSERT INTO read_grants VALUES('operator-a','host.discovery.read','host-discovery-target','candidate-a',1,'active','now','now')`)
	repo := store.NewHostDiscoveryRepository(authority)
	revisions := store.NewPlanRepository(authority)
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	observations, err := planengine.NewStateObservationReader(revisions)
	if err != nil {
		t.Fatal(err)
	}
	plans, err := planengine.NewService(planengine.Config{HostDiscoveryTargets: repo, Repository: revisions, Observations: observations, Clock: time.Now, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if err != nil {
		t.Fatal(err)
	}
	requestNumber := 0
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) {
		requestNumber++
		return fmt.Sprintf("request-discovery-%d", requestNumber), nil
	})
	app, err := api.NewApplication(api.Config{Authority: authority, Authorizer: store.NewReadAuthorizer(authority), Reads: store.NewReadRepository(authority), Results: factory})
	if err != nil {
		t.Fatal(err)
	}
	policy := store.NewEffectiveAuthorizationRepository(authority)
	if err := api.RegisterDeclarationPlanOperations(app, api.DeclarationPlanConfig{Declarations: declarations, Plans: plans, Results: factory, Authorization: api.EffectiveAuthorizationConfig{Authorizer: authorization.NewEvaluator(policy), Recorder: policy, Clock: time.Now}}); err != nil {
		t.Fatal(err)
	}
	target, private, calls := discoveryAcceptancePeer(t, pointVersion)
	target.ExpectedVersion = expectedVersion
	resolver := &discoveryAcceptanceResolver{key: private}
	registry := adapter.NewRegistry()
	if err := registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "fixture-discovery", ConsumerID: hostdiscovery.Consumer, ProfileID: target.ProfileID, CapabilityID: "credential.discovery.read", Enabled: true}, resolver); err != nil {
		t.Fatal(err)
	}
	activated := time.Now().UTC().Format(time.RFC3339)
	borrower := hostDiscoveryCredentials{targets: repo, references: recoveryReferenceStub{reference: generated.CredentialReference{ReferenceID: target.CredentialReferenceID, ConsumerID: hostdiscovery.Consumer, PurposeID: hostdiscovery.Purpose, TargetID: target.TargetID, ResolverID: "fixture-discovery", MaterialVersion: target.MaterialVersion, Status: "active", ActivatedAt: &activated, VerifiedConsumerIDs: []string{hostdiscovery.Consumer}}}, profiles: recoveryProfileStub{profile: store.GateAppliedProfile{ProfileID: target.ProfileID, Capabilities: []string{"credential.discovery.read"}}}, resolvers: registry}
	service := &hostdiscovery.Service{Repository: repo, Collector: &collector.Collector{Borrower: borrower, Clock: func() time.Time { fixtureNow = fixtureNow.Add(time.Second); return fixtureNow }}}
	if err := api.RegisterHostDiscoveryOperations(app, api.HostDiscoveryOperations{Service: service, Targets: repo, Declarations: declarations, Results: factory}); err != nil {
		t.Fatal(err)
	}
	principal := identity.Principal{ID: "operator-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	request := func(method, path string, input any, authenticated bool) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(input)
		if input == nil {
			raw = nil
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		if input != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if authenticated {
			r = r.WithContext(identity.WithVerifiedPrincipal(r.Context(), principal))
		}
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		return w
	}
	decode := func(w *httptest.ResponseRecorder, out any) {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
		}
		var envelope struct {
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(w.Body.Bytes(), &envelope) != nil || json.Unmarshal(envelope.Data, out) != nil {
			t.Fatalf("invalid envelope %s", w.Body.String())
		}
	}
	discoveryRequest := generated.HostDiscoveryRequest{Schema: generated.SchemaIDHostDiscoveryRequest, SchemaVersion: "1.0.0", TargetID: target.TargetID, TargetRevision: 1, IdempotencyKey: "scan-a"}
	if w := request("POST", "/api/v1/host-observations", discoveryRequest, false); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", w.Code)
	}
	draftReq := generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: "activate", IdempotencyKey: "draft-a"}
	declarationID := "discovery-draft-" + hostdiscovery.Digest(draftReq)[7:39]
	grant("declaration.author", "declaration", declarationID, "author")
	var draft generated.HostDiscoveryTargetDraftSubmission
	decode(request("POST", "/api/v1/host-discovery-targets/draft", draftReq, true), &draft)
	discoveryRequest.ExpectedStateRevision = draft.StateRevision
	if w := request("POST", "/api/v1/host-observations", discoveryRequest, true); w.Code == http.StatusOK || calls.Load() != 0 || resolver.calls != 0 {
		t.Fatal("inert draft enabled connection")
	}
	declaration, err := declarations.Get(ctx, draft.DeclarationID, 1)
	if err != nil {
		t.Fatal(err)
	}
	current, err := revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := observations.CurrentFingerprint(ctx, declaration.DeclarationID, declaration.Operations)
	if err != nil {
		t.Fatal(err)
	}
	created, err := plans.Create(ctx, planengine.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: "session-discovery"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: declaration.DeclarationID, DeclarationRevision: declaration.Revision, ExpectedStateRevision: current.StateRevision, ObservationFingerprint: fingerprint, IdempotencyKey: "plan-a", Extensions: declaration.Extensions})
	if err != nil {
		t.Fatal(err)
	}
	plan := created.Plan
	acknowledger, err := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(authority), Plans: lifecycleAcceptancePlanReader{plans}, Authorizer: lifecycleAcceptanceAuthorizer{}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	human := identity.Principal{ID: "human-a", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
	card, err := acknowledger.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: "fixture-nonce"}, plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := acknowledger.Decide(ctx, acknowledgement.Candidate{Human: human, AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, Nonce: card.Nonce, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, ExpiresAt: mustAcceptanceTime(t, plan.ExpiresAt), DecidedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	effect := &runengine.HostDiscoveryTargetEffect{Repository: repo, Approvals: store.NewAcknowledgementRepository(authority), RecoveryPrecheck: discoveryRecoveryFixture{}}
	if !qualified {
		effect.RecoveryPrecheck = runengine.UnavailableGateVerifier{}
	}
	engine, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(authority), Plans: plans, Admission: runengine.NewAdmissionGate(acknowledger, time.Now), Adapters: adapter.NewRegistry(), Core: runengine.CoreRouter{DiscoveryTarget: effect}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	branch := "human"
	decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-discovery", PrincipalID: human.ID, Action: "execute", TargetID: plan.Operations[0].TargetID, Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, PlanDigest: plan.PlanDigest, DecidedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	submission := runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, IdempotencyKey: "run-a", Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: audit.Attribution{AuthenticatedPrincipalID: principal.ID, AuthenticatedPrincipalMethod: principal.Method, ResponsibleHumanPrincipalID: &human.ID}}
	applied, err := engine.Submit(ctx, submission)
	if !qualified {
		var targets int
		if queryErr := db.QueryRow(`SELECT COUNT(*) FROM host_discovery_targets`).Scan(&targets); queryErr != nil {
			t.Fatal(queryErr)
		}
		if err == nil || applied.Status == "succeeded" || targets != 0 || calls.Load() != 0 || resolver.calls != 0 {
			t.Fatal("missing recovery proof allowed activation or connection")
		}
		return
	}
	if err != nil || applied.Status != "succeeded" {
		t.Fatalf("activation failed: %+v %v", applied, err)
	}
	if calls.Load() != 0 || resolver.calls != 0 {
		t.Fatal("activation contacted host")
	}
	current, err = revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	discoveryRequest.ExpectedStateRevision = current.StateRevision
	var observed generated.HostDiscoverySubmission
	decode(request("POST", "/api/v1/host-observations", discoveryRequest, true), &observed)
	if observed.Observation.Status != "untrusted" || !slices.Contains(observed.Observation.Blockers, "hardening-unverified") || calls.Load() != 10 || resolver.calls != 1 {
		t.Fatalf("bad observation: %+v commands=%d resolves=%d", observed, calls.Load(), resolver.calls)
	}
	firstCapture := captureStart.Add(time.Second).Format(time.RFC3339)
	lastCapture := captureStart.Add(10 * time.Second).Format(time.RFC3339)
	if observed.Observation.Facts[0].CapturedAt != firstCapture || observed.Observation.Facts[len(observed.Observation.Facts)-1].CapturedAt != lastCapture || observed.Observation.ObservedAt != firstCapture || observed.Observation.ExpiresAt != captureStart.Add(15*time.Minute+time.Second).Format(time.RFC3339) {
		t.Fatal("capture provenance or expiry used persistence time")
	}
	if pointVersion == "12.9" {
		if !slices.Contains(observed.Observation.Blockers, "os-version-conflict") {
			t.Fatal("conflicting version facts not blocked")
		}
		retained := map[string]string{}
		for _, fact := range observed.Observation.Facts {
			retained[fact.Name] = fact.Value
		}
		if retained["os.version"] != "13" || retained["os.point-version"] != "12.9" {
			t.Fatal("conflicting version claims overwritten")
		}
	}
	if resolver.value == nil || len(resolver.value.Bytes()) != 0 {
		t.Fatal("credential not closed")
	}
	var replay generated.HostDiscoverySubmission
	decode(request("POST", "/api/v1/host-observations", discoveryRequest, true), &replay)
	if replay.Created || replay.Observation.ContentDigest != observed.Observation.ContentDigest || calls.Load() != 10 {
		t.Fatal("retry recollected")
	}
	var fetched generated.HostObservation
	decode(request("GET", "/api/v1/host-observations/"+observed.Observation.ObservationID, nil, true), &fetched)
	exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE capability='host.discovery.read'`)
	if w := request("GET", "/api/v1/host-observations/"+observed.Observation.ObservationID, nil, true); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "synthetic-serial") {
		t.Fatal("revoked read disclosed facts")
	}
	for _, table := range []string{"gate_applied_evidence", "gate_applied_profiles"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatal("discovery changed admission")
		}
	}
}

type discoveryAcceptanceResolver struct {
	key   []byte
	calls int
	value *credentialref.Value
}

func (r *discoveryAcceptanceResolver) Resolve(context.Context, credentialref.StepBinding) (*credentialref.Value, error) {
	r.calls++
	r.value, _ = credentialref.NewValue(r.key)
	return r.value, nil
}
func discoveryAcceptancePeer(t *testing.T, pointVersion string) (generated.HostDiscoveryTarget, []byte, *atomic.Int32) {
	t.Helper()
	_, hostPrivate, _ := ed25519.GenerateKey(rand.Reader)
	host, _ := ssh.NewSignerFromKey(hostPrivate)
	_, userPrivate, _ := ed25519.GenerateKey(rand.Reader)
	user, _ := ssh.NewSignerFromKey(userPrivate)
	block, _ := ssh.MarshalPrivateKey(userPrivate, "")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	calls := &atomic.Int32{}
	done := make(chan struct{})
	var current atomic.Pointer[net.Conn]
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		current.Store(&conn)
		defer conn.Close()
		config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(key.Marshal(), user.PublicKey().Marshal()) {
				return nil, fmt.Errorf("wrong fixture key")
			}
			return nil, nil
		}}
		config.AddHostKey(host)
		server, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer server.Close()
		go func() {
			for req := range requests {
				t.Errorf("unexpected global SSH request %s", req.Type)
				_ = req.Reply(false, nil)
			}
		}()
		commands := []string{"/usr/bin/cat /etc/os-release", "/usr/bin/cat /etc/debian_version", "/usr/bin/uname -m", "/usr/bin/cat /etc/machine-id", "/usr/bin/cat /sys/class/dmi/id/product_uuid", "/usr/bin/cat /sys/class/dmi/id/product_serial", "/usr/bin/cat /proc/meminfo", "/usr/bin/cat /sys/devices/system/cpu/online", "/usr/bin/lsblk --json --bytes --output NAME,TYPE,SIZE", "/usr/bin/ip -j link show"}
		outputs := []string{"ID=debian\nVERSION_ID=13\n", pointVersion + "\n", "x86_64\n", "0123456789abcdef0123456789abcdef\n", "01234567-89ab-cdef-0123-456789abcdef\n", "synthetic-serial\n", "MemTotal: 1024 kB\n", "0-3\n", `{"blockdevices":[{"name":"vda","type":"disk","size":1024}]}`, `[{"ifname":"eth0","link_type":"ether","address":"02:00:00:00:00:01"}]`}
		for ch := range channels {
			if ch.ChannelType() != "session" {
				t.Error("unexpected channel")
				_ = ch.Reject(ssh.Prohibited, "")
				continue
			}
			channel, requests, err := ch.Accept()
			if err != nil {
				return
			}
			for req := range requests {
				var payload struct{ Command string }
				index := int(calls.Add(1)) - 1
				if req.Type != "exec" || ssh.Unmarshal(req.Payload, &payload) != nil || index >= len(commands) || payload.Command != commands[index] {
					t.Error("unexpected request")
					_ = req.Reply(false, nil)
					break
				}
				_ = req.Reply(true, nil)
				_, _ = channel.Write([]byte(outputs[index]))
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				break
			}
			_ = channel.Close()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		if c := current.Load(); c != nil {
			_ = (*c).Close()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("peer did not stop")
		}
	})
	return generated.HostDiscoveryTarget{Schema: generated.SchemaIDHostDiscoveryTarget, SchemaVersion: "1.0.0", TargetID: "candidate-a", Revision: 1, Address: "127.0.0.1", Port: int64(listener.Addr().(*net.TCPAddr).Port), User: "inspect", HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(host.PublicKey()))), ProfileID: "portable-test", CredentialReferenceID: "credential-a", MaterialVersion: "version-a", ExpectedOS: "debian", ExpectedVersion: "13", ExpectedArchitecture: "amd64"}, pem.EncodeToMemory(block), calls
}

// Explicit synthetic recovery proof, never production qualification.
type discoveryRecoveryFixture struct{}

func (discoveryRecoveryFixture) VerifySecretStep(_ context.Context, p generated.Plan, op generated.PlanOperation) error {
	if p.Risk != "control-plane" || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || op.AdapterID != "core.host-discovery-target" {
		return hostdiscovery.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	return nil
}
