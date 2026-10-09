//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	transport "github.com/vegastack/vegastack-labs/internal/adapter/hostaction"
	"github.com/vegastack/vegastack-labs/internal/adapters/slack"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
	"golang.org/x/crypto/ssh"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Software composition only: real temporary SQLite and approval/run authority,
// synthetic credentials, profile and loopback peer. This is not native qualification.
func TestHostActionAcceptance(t *testing.T) {
	for _, mode := range []string{"success", "revoked-automation", "missing-action-ack"} {
		t.Run(mode, func(t *testing.T) { hostActionAcceptance(t, mode) })
	}
}

type hostActionAcceptanceHooks struct {
	Peer           func(*testing.T, ssh.Signer, ActionSigner, *atomic.Int32, string) int
	DenialCode     string
	EnrollmentOnly bool
	Challenge      func(*testing.T, *sql.DB, *time.Time, *HostActionAuthority, generated.HostActionEnvelope, generated.HostActionChallenge) (generated.HostActionAuthorization, error)
	Enrollment     func(*testing.T, hostActionEnrollmentFixture) adapter.CredentialResolver
}
type hostActionEnrollmentFixture struct {
	Context             context.Context
	Authority           *store.Store
	DB                  *sql.DB
	Clock               func() time.Time
	AdvanceClock        func(time.Duration)
	Declarations        *change.Service
	App                 *api.Application
	Results             *result.Factory
	Key                 []byte
	DestinationIdentity string
	TargetDigest        string
	Target              generated.HostDiscoveryTarget
	Signer              ActionSigner
	Directory           string
}

func hostActionAcceptance(t *testing.T, actionMode string, options ...hostActionAcceptanceHooks) {
	var hooks hostActionAcceptanceHooks
	if len(options) > 0 {
		hooks = options[0]
	}

	principal := identity.Principal{ID: "operator-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	ctx := identity.WithVerifiedPrincipal(context.Background(), principal)
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
		exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?, ?,NULL,1,'active','now','now')`, "grant-"+hostdiscovery.Digest([]string{capability, id})[7:25], action, capability, kind, id)
	}
	for _, c := range []string{"host.discovery.collect", "host.discovery.read"} {
		grant(c, "host-discovery-target", "candidate-a", "read")
	}
	grant("host.adoption.prepare", "host-discovery-target", "candidate-a", "author")
	grant("host.read", "host", "synthetic-host", "read")
	exec(`INSERT INTO read_principals VALUES('operator-a','active',1,'now','now')`)
	exec(`INSERT INTO read_grants VALUES('operator-a','host.discovery.read','host-discovery-target','candidate-a',1,'active','now','now')`)
	repo := store.NewHostAdoptionRepository(authority)
	revisions := store.NewPlanRepository(authority)
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	observations, err := planengine.NewStateObservationReader(revisions)
	if err != nil {
		t.Fatal(err)
	}
	plans, err := planengine.NewService(planengine.Config{HostAdoptions: repo, Repository: revisions, Observations: observations, Clock: time.Now, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
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
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}

	actionSigner := &actionTestSigner{key: private}
	wrote := new(atomic.Int32)
	peer := hostActionAcceptancePeer
	if hooks.Peer != nil {
		peer = hooks.Peer
	}
	port := peer(t, key, actionSigner, wrote, directory)
	target := generated.HostDiscoveryTarget{Schema: generated.SchemaIDHostDiscoveryTarget, SchemaVersion: "1.0.0", TargetID: "candidate-a", Revision: 1, Address: "127.0.0.1", Port: int64(port), User: "inspect", HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey()))), ProfileID: "debian-13-amd64", CredentialReferenceID: "fixture-credential", MaterialVersion: "fixture-version", ExpectedOS: "debian", ExpectedVersion: "13", ExpectedArchitecture: "amd64"}
	target.ProfileID = "debian-13-amd64"
	dr := generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: "activate", IdempotencyKey: "fixture-target"}
	raw, _ := json.Marshal(dr)
	digest := hostdiscovery.Digest(dr)
	exec(`INSERT INTO host_discovery_drafts VALUES('fixture-target','candidate-a',1,0,'activate',?,?,'operator-a',0,0)`, digest, raw)
	hash := hostdiscovery.Digest("fixture")
	exec(`INSERT INTO declaration_revisions VALUES('fixture-declaration',1,'host.discovery-target',0,0,?,?,'draft',?,'now','operator-a','session-a')`, hash, hash, []byte(`{}`))
	exec(`INSERT INTO immutable_plans VALUES('fixture-plan',?,'fixture-declaration',1,1,0,?,?,?,?,?,?,'2026-01-01T00:00:00Z','2026-12-01T00:00:00Z')`, hash, hash, hash, hash, []byte(`{}`), "fixture", hash)
	exec(`INSERT INTO host_discovery_targets VALUES('candidate-a',1,'fixture-target','active','fixture-plan',0)`)
	now := clock().UTC().Truncate(time.Second)
	facts := []generated.HostDiscoveryFact{}
	for _, v := range []struct{ n, v, o string }{{"os.id", "debian", "os-release"}, {"os.version", "13", "os-release"}, {"architecture", "amd64", "architecture"}, {"product-serial", "synthetic-serial", "product-serial"}} {
		f := hostdiscovery.Fact(v.n, v.v, v.o)
		f.CapturedAt = now.Format(time.RFC3339)
		facts = append(facts, f)
	}
	obs := generated.HostObservation{Schema: generated.SchemaIDHostObservation, SchemaVersion: "1.0.0", ObservationID: "fixture-observation", TargetID: target.TargetID, TargetRevision: 1, TargetDigest: digest, Collector: hostdiscovery.CollectorID, CollectorVersion: "1.0.0", ObservedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(15 * time.Minute).Format(time.RFC3339), Status: "incomplete", Facts: facts, Blockers: []string{"hardening-unverified", "role-admission-unverified", "identity-class-unverified"}}
	obs.ContentDigest = hostdiscovery.Digest(obs)
	raw, _ = json.Marshal(obs)
	exec(`INSERT INTO host_discovery_attempts VALUES('fixture-observation','operator-a',?,?,'candidate-a',1,?,1,0,0,'later',?)`, hash, hash, digest, []byte(`{}`))
	exec(`INSERT INTO host_observations VALUES('fixture-observation','candidate-a',1,?,?,0,0)`, raw, hostdiscovery.Digest(obs))
	req := generated.HostAdoptionRequest{Schema: generated.SchemaIDHostAdoptionRequest, SchemaVersion: "1.0.0", HostID: "synthetic-host", ObservationID: obs.ObservationID, ObservationDigest: obs.ContentDigest, IdempotencyKey: "adopt-one", Confirmation: generated.HostIdentityConfirmation{Schema: generated.SchemaIDHostIdentityConfirmation, SchemaVersion: "1.0.0", TargetRevision: 1, TargetDigest: digest, IdentityClass: "physical", IdentityKind: "product-serial", IdentityDigest: hostadoption.IdentityDigest("product-serial", "synthetic-serial"), ConfirmedAt: now.Format(time.RFC3339)}}
	exec(`UPDATE system_meta SET state_revision=1 WHERE id=1`)
	req.ExpectedStateRevision = 1
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

	if err := api.RegisterHostAdoptionOperations(app, api.HostAdoptionOperations{Hosts: repo, Declarations: declarations, Results: factory}); err != nil {
		t.Fatal(err)
	}
	declarationID := "host-adoption-" + hostadoption.Digest(req)[7:39]
	grant("declaration.author", "declaration", declarationID, "author")
	var draft generated.HostAdoptionSubmission
	decode(request("POST", "/api/v1/host-adoptions/draft", req, true), &draft)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM managed_hosts`).Scan(&n); err != nil || n != 0 {
		t.Fatal("draft created host", err)
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
	for _, g := range []struct{ action, cap, kind string }{{"acknowledge", "plan.acknowledge", "plan-target"}, {"execute", "host.adopt", "execution-target"}} {
		exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?,?,'human',1,'active','now','now')`, g.action+"-host", g.action, g.cap, g.kind, draft.DraftID)
	}
	if !strings.Contains(created.Readable, "Administrator attestation") || plan.HostAdoption == nil {
		t.Fatal("missing informed confirmation")
	}
	acknowledger, err := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(authority), Plans: lifecycleAcceptancePlanReader{plans}, Authorizer: lifecycleAcceptanceAuthorizer{}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	human := identity.Principal{ID: "operator-a", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
	card, err := acknowledger.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: "fixture-nonce"}, plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := acknowledger.Decide(ctx, acknowledgement.Candidate{Human: human, AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, Nonce: card.Nonce, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, ExpiresAt: mustAcceptanceTime(t, plan.ExpiresAt), DecidedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	effect := &runengine.HostAdoptionEffect{Repository: repo, Approvals: store.NewAcknowledgementRepository(authority)}
	engine, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(authority), Plans: plans, Admission: runengine.NewAdmissionGate(acknowledger, time.Now), Adapters: adapter.NewRegistry(), Core: runengine.CoreRouter{Adoption: effect}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	branch := "human"
	decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-discovery", PrincipalID: human.ID, Action: "execute", TargetID: plan.Operations[0].TargetID, Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, PlanDigest: plan.PlanDigest, DecidedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	submission := runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, IdempotencyKey: "run-a", Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: audit.Attribution{AuthenticatedPrincipalID: principal.ID, AuthenticatedPrincipalMethod: principal.Method, ResponsibleHumanPrincipalID: &human.ID}}
	applied, err := engine.Submit(ctx, submission)

	if err != nil || applied.Status != "succeeded" {
		t.Fatalf("registration failed: %+v %v", applied, err)
	}
	var host generated.ManagedHost
	decode(request("GET", "/api/v1/hosts/synthetic-host", nil, true), &host)
	if host.Status != "adopted-unadmitted" || host.HostID != "synthetic-host" {
		t.Fatal("bad host status")
	}
	for _, table := range []string{"gate_applied_evidence", "gate_applied_profiles", "credential_reference_versions"} {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatal("registration changed authority", table, err)
		}
	}

	// Explicit synthetic precondition; this does not install or qualify systemd credentials.
	pk, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	var credentialResolver adapter.CredentialResolver = hostActionAcceptanceCredential{key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})}
	if hooks.Enrollment != nil {
		credentialResolver = hooks.Enrollment(t, hostActionEnrollmentFixture{Context: ctx, Authority: authority, DB: db, Clock: clock, AdvanceClock: func(d time.Duration) { fixtureNow = fixtureNow.Add(d) }, Declarations: declarations, App: app, Results: factory, Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), DestinationIdentity: hostadoption.IdentityDigest("product-serial", "synthetic-serial"), TargetDigest: digest, Target: target, Signer: actionSigner, Directory: directory})

		if hooks.EnrollmentOnly {
			return
		}
	} else {
		exec(`INSERT INTO credential_reference_versions VALUES('synthetic-version','action-key','host-action','host-action-ssh','synthetic-host','native-systemd','version-a',?,'active',1,0,?,?,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, hash, time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), []byte(`["host-action"]`), hash)
	}

	exec(`INSERT INTO effective_authorization_principals VALUES('automation-a','agent','active',1,'now','now')`)
	exec(`INSERT INTO effective_authorization_grants VALUES('automation-action','automation-a','infrastructure-admin','execute','host.action.execute','execution-target','synthetic-host','human',1,'active','now','now')`)
	grant("host.action.prepare", "host", "synthetic-host", "author")
	actionRepo := store.NewHostActionRepository(authority)
	credentials := store.NewCredentialRepository(authority)
	if _, fixtureErr := credentials.GetActiveVersion(ctx, "action-key", 0); fixtureErr != nil {
		t.Fatalf("invalid synthetic credential metadata: %v", fixtureErr)
	}
	plans, err = planengine.NewService(planengine.Config{HostActions: actionRepo, HostActionCredentials: credentials, Repository: revisions, Observations: observations, Clock: time.Now, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if err != nil {
		t.Fatal(err)
	}
	if err = api.RegisterHostActionOperations(app, api.HostActionOperations{Hosts: actionRepo, Declarations: declarations, Credentials: credentials, Results: factory}); err != nil {
		t.Fatal(err)
	}
	current, err = revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	identityDigest := hostadoption.IdentityDigest("product-serial", "synthetic-serial")
	actionRequest := generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", ActionID: "test.write-file", ActionVersion: "1.0.0", ActionInput: "{}", ActionInputDigest: hostaction.BytesDigest([]byte("{}")), HostID: "synthetic-host", TargetRevision: 1, TargetDigest: digest, AutomationPrincipalID: "automation-a", CallerUID: 1001, CredentialReferenceID: "action-key", CredentialMaterialVersion: "version-a", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: digest, HostIdentityDigest: identityDigest}, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: "action-one"}
	grant("declaration.author", "declaration", hostaction.DraftID(actionRequest), "author")
	var actionDraft generated.HostActionSubmission
	decode(request("POST", "/api/v1/host-actions/draft", actionRequest, true), &actionDraft)
	declaration, err = declarations.Get(ctx, actionDraft.DeclarationID, 1)
	if err != nil {
		t.Fatal(err)
	}
	current, err = revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err = observations.CurrentFingerprint(ctx, declaration.DeclarationID, declaration.Operations)
	if err != nil {
		t.Fatal(err)
	}
	created, err = plans.Create(ctx, planengine.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: "session-action"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: declaration.DeclarationID, DeclarationRevision: declaration.Revision, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, ObservationFingerprint: fingerprint, IdempotencyKey: "plan-action", Extensions: declaration.Extensions})
	if err != nil {
		t.Fatal(err)
	}
	plan = created.Plan
	if plan.HostAction == nil {
		t.Fatal("missing sealed action")
	}
	if risk, classifyErr := authorization.ClassifyPlan(plan); classifyErr != nil || risk != authorization.RiskInfrastructure {
		t.Fatalf("host action has no matching production risk classification: %s %v", risk, classifyErr)
	}
	for _, g := range []struct{ action, cap, kind string }{{"acknowledge", "plan.acknowledge", "plan-target"}, {"execute", "host.action.execute", "execution-target"}} {
		if hooks.Enrollment != nil && g.action == "acknowledge" {
			var existing int
			if err := db.QueryRow(`SELECT COUNT(*) FROM effective_authorization_grants WHERE principal_id='operator-a' AND role_id='control-plane-admin' AND action=? AND capability=? AND resource_kind=? AND resource_id='synthetic-host' AND branch='human' AND grant_revision=1 AND status='active'`, g.action, g.cap, g.kind).Scan(&existing); err != nil {
				t.Fatal(err)
			}
			if existing == 1 {
				continue
			}
			if existing != 0 {
				t.Fatal("ambiguous enrollment acknowledgement grant")
			}
		}
		exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?,'synthetic-host','human',1,'active','now','now')`, "action-"+g.action, g.action, g.cap, g.kind)
	}
	acknowledger, err = acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(authority), Plans: lifecycleAcceptancePlanReader{plans}, Authorizer: authorization.NewEvaluator(policy), Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	card, err = acknowledger.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: "action-nonce"}, plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	approved = hostActionAcceptanceSlackApproval(t, acknowledger, card)
	liveAuthority, err := NewHostActionAuthority(actionRepo, actionSigner, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	var challengeAuthority transport.Authority = liveAuthority
	if hooks.Challenge != nil {
		challengeAuthority = hostActionChallengeFunc(func(ctx context.Context, e generated.HostActionEnvelope, c generated.HostActionChallenge) (generated.HostActionAuthorization, error) {
			return hooks.Challenge(t, db, &fixtureNow, liveAuthority, e, c)
		})
	}
	actionAdapter, err := transport.New(hostActionTargets{repository: actionRepo, allowed: []string{identityDigest}}, &HostActionBundleIssuer{Repository: actionRepo, Signer: actionSigner, Clock: time.Now}, challengeAuthority)
	if err != nil {
		t.Fatal(err)
	}
	registry := adapter.NewRegistry()
	if err = registry.Register(hostaction.AdapterID, actionAdapter); err != nil {
		t.Fatal(err)
	}
	if err = registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: "host-action", ProfileID: "synthetic-profile", CapabilityID: "synthetic-capability", Enabled: true}, credentialResolver); err != nil {
		t.Fatal(err)
	}
	engine, err = runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(authority), Plans: plans, Admission: runengine.NewAdmissionGate(acknowledger, time.Now), Adapters: registry, SecretGate: hostActionGate{targets: actionRepo, allowed: []string{identityDigest}}, CredentialStep: &runengine.CredentialStep{Bindings: credentials, Resolvers: registry, Profiles: hostActionAcceptanceProfile{}, Plans: plans, Clock: time.Now}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	decision.PlanDigest = plan.PlanDigest
	decision.TargetID = "synthetic-host"
	decision.DecisionID = "decision-action"
	submission = runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, IdempotencyKey: "run-action", Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: audit.Attribution{AuthenticatedPrincipalID: principal.ID, AuthenticatedPrincipalMethod: principal.Method, ResponsibleHumanPrincipalID: &human.ID}}
	if actionMode == "missing-action-ack" {
		submission.Acknowledgement = nil
	}
	if actionMode == "revoked-automation" {
		exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='automation-action'`)
	}
	applied, err = engine.Submit(ctx, submission)
	if actionMode != "success" {
		expectedCode := generated.ErrorCodeExecutionFailed
		if hooks.DenialCode != "" {
			expectedCode = hooks.DenialCode
		}
		if actionMode == "missing-action-ack" {
			expectedCode = generated.ErrorCodeApprovalRequired
		}
		if runengine.Code(err) != expectedCode {
			t.Fatalf("denial exercised wrong boundary: wanted %s got %v", expectedCode, err)
		}
		if (err == nil && applied.Status == "succeeded") || wrote.Load() != 0 || (actionMode != "challenge-denial" && actionSigner.calls != 0) {
			t.Fatalf("denial changed peer: status=%s error=%v writes=%d", applied.Status, err, wrote.Load())
		}
		if _, statErr := os.Stat(filepath.Join(directory, "action-result")); !os.IsNotExist(statErr) {
			t.Fatalf("denied action created output file: %v", statErr)
		}
		return
	}
	if err != nil || applied.Status != "succeeded" || wrote.Load() != 1 {
		t.Fatalf("action failed: %+v error=%v writes=%d", applied, err, wrote.Load())
	}
	if actionSigner.calls != 2 {
		t.Fatalf("expected envelope and fresh authorization signatures, got %d", actionSigner.calls)
	}
	var qualified int
	if err = db.QueryRow(`SELECT COUNT(*) FROM gate_applied_evidence`).Scan(&qualified); err != nil || qualified != 0 {
		t.Fatal("software action manufactured native evidence", err)
	}
}

type hostActionAcceptanceCredential struct{ key []byte }

func (r hostActionAcceptanceCredential) Resolve(context.Context, credentialref.StepBinding) (*credentialref.Value, error) {
	return credentialref.NewValue(append([]byte(nil), r.key...))
}

type hostActionAcceptanceProfile struct{}

func (hostActionAcceptanceProfile) GetAppliedProfileScope(context.Context) (store.GateAppliedProfile, error) {
	return store.GateAppliedProfile{ProfileID: "synthetic-profile", Capabilities: []string{"synthetic-capability"}, StateRevision: 1}, nil
}

type hostActionAcceptanceHandler struct {
	path   string
	writes *atomic.Int32
}

func (h hostActionAcceptanceHandler) Lookup(id, version string) (hostaction.Handler, bool) {
	return h, id == "test.write-file" && version == "1.0.0"
}
func (h hostActionAcceptanceHandler) Execute(_ context.Context, b generated.HostActionBundle) (generated.HostActionResult, error) {
	d, _ := hostaction.BundleDigest(b)
	if err := os.WriteFile(h.path, []byte("synthetic action"), 0600); err != nil {
		return generated.HostActionResult{}, err
	}
	h.writes.Add(1)
	return generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: d, ResultDigest: hostaction.Digest("synthetic action"), Status: "succeeded", Changed: true, EffectObserved: true, Reason: "verified"}, nil
}
func (h hostActionAcceptanceHandler) Verify(_ context.Context, _ generated.HostActionBundle, _ generated.HostActionResult) error {
	raw, err := os.ReadFile(h.path)
	if err != nil {
		return err
	}
	if string(raw) != "synthetic action" {
		return fmt.Errorf("wrong synthetic result")
	}
	return nil
}
func hostActionAcceptancePeer(t *testing.T, key ssh.Signer, signer ActionSigner, writes *atomic.Int32, directory string) int {
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
		conn, err := listener.Accept()
		if err != nil {
			return
		}
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
				err = hostaction.RunOnce(context.Background(), ch, ch, policy, receipts, hostActionAcceptanceHandler{path: filepath.Join(directory, "action-result"), writes: writes}, time.Now, rand.Reader)
				code := uint32(0)
				if err != nil {
					code = 1
				}
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
				return
			}
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

// The transport is synthetic; provider envelope decoding, identity binding and
// current store-backed acknowledgement authorization are production paths.
type hostActionAcceptanceSlackCredential struct{}

func (hostActionAcceptanceSlackCredential) Resolve(context.Context, credentialref.Reference) ([]byte, error) {
	return []byte("synthetic-token-for-local-test"), nil
}
func hostActionAcceptanceSlackApproval(t *testing.T, service *acknowledgement.Service, card acknowledgement.RequestCard) generated.Acknowledgement {
	t.Helper()
	wire := &setupAcceptanceTransport{cards: make(chan acknowledgement.RequestCard, 1), incoming: make(chan []byte, 1)}
	results := make(chan generated.Acknowledgement, 1)
	failures := make(chan error, 1)
	sink := slack.CandidateSinkFuncs{SubmitFunc: func(ctx context.Context, c acknowledgement.Candidate) error {
		a, err := service.Decide(ctx, c)
		if err != nil {
			failures <- err
			return err
		}
		results <- a
		return nil
	}, RejectFunc: func(_ context.Context, r acknowledgement.AdapterRejection) error {
		err := fmt.Errorf("synthetic Slack event rejected: %v", r)
		failures <- err
		return err
	}}
	cfg := slack.Config{AppTokenReference: credentialref.Reference{ID: "synthetic-app", Consumer: "slack-acknowledgement"}, BotTokenReference: credentialref.Reference{ID: "synthetic-bot", Consumer: "slack-acknowledgement"}, WorkspaceID: "T-setup", SlackUserID: "U-setup", HumanID: "operator-a", AuthorityID: "fixture-authority", ChannelID: "C-setup", ApproveActionID: "approve", RejectActionID: "reject", ReconnectDelay: time.Millisecond}
	adapter, err := slack.NewAdapter(cfg, hostActionAcceptanceSlackCredential{}, wire, sink)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- adapter.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("synthetic Slack adapter failed to stop")
		}
	}()
	if err = adapter.Publish(ctx, card); err != nil {
		t.Fatal(err)
	}
	delivered := <-wire.cards
	(&setupAcceptance{transport: wire}).send(delivered, nil)
	select {
	case a := <-results:
		return a
	case err := <-failures:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal("synthetic Slack approval timed out")
	}
	return generated.Acknowledgement{}
}

type hostActionChallengeFunc func(context.Context, generated.HostActionEnvelope, generated.HostActionChallenge) (generated.HostActionAuthorization, error)

func (f hostActionChallengeFunc) Authorize(ctx context.Context, e generated.HostActionEnvelope, c generated.HostActionChallenge) (generated.HostActionAuthorization, error) {
	return f(ctx, e, c)
}
