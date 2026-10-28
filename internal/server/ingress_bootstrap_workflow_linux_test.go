//go:build linux

package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	cloud "github.com/vegastack/vegastack-labs/internal/adapter/cloudflare"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This fixture exercises real SQLite/API/plan/ack/run boundaries. It deliberately
// substitutes provider effects and the native-custody gate; it is not live proof.
type ingressBootstrapAcceptanceAuthority struct{ ingressAcceptanceAuthority }

func (a ingressBootstrapAcceptanceAuthority) ReserveBootstrap(ctx context.Context, d ingress.Staged, b adapter.ExactExecutionBinding, s ingress.Snapshot) error {
	return a.repository.ReserveBootstrap(ctx, d, b, s)
}

type ingressBootstrapAcceptanceBackend struct{ writes, dnsWrites int }

func (b *ingressBootstrapAcceptanceBackend) ObserveIngress(context.Context, generated.IngressChange, *credentialref.Value) (ingress.Snapshot, error) {
	panic("ordinary path")
}
func (b *ingressBootstrapAcceptanceBackend) MutateIngress(context.Context, generated.IngressChange, *credentialref.Value, *credentialref.Value, *credentialref.Value) error {
	panic("ordinary path")
}
func (b *ingressBootstrapAcceptanceBackend) ObserveBootstrap(_ context.Context, c generated.IngressChange, _ *credentialref.Value) (ingress.Snapshot, error) {
	if c.ResourceID == "" {
		return ingress.Snapshot{Digest: ingress.Digest("before")}, nil
	}
	return ingress.Snapshot{Present: true, ResourceID: c.ResourceID, Digest: ingress.Digest(c.ResourceID)}, nil
}
func (b *ingressBootstrapAcceptanceBackend) MutateBootstrap(_ context.Context, c generated.IngressChange, _, _ *credentialref.Value) (ingress.Snapshot, error) {
	b.writes++
	if c.Action == "bootstrap-cutover" {
		b.dnsWrites++
	}
	id := map[string]string{"bootstrap-tunnel": "11111111-1111-4111-8111-111111111111", "bootstrap-group": "22222222-2222-4222-8222-222222222222", "bootstrap-app": "33333333-3333-4333-8333-333333333333", "bootstrap-policy": "44444444-4444-4444-8444-444444444444", "bootstrap-seed": "11111111-1111-4111-8111-111111111111", "bootstrap-cutover": c.DNSRecordID}[c.Action]
	return ingress.Snapshot{Present: true, ResourceID: id, Digest: ingress.Digest(id)}, nil
}

func TestIngressBootstrapAPIPlansAcknowledgementAndSameRecordCutover(t *testing.T) {
	ctx := context.Background()
	directory, e := os.MkdirTemp("/var/tmp", "vsk330-fixture-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if e := os.Chmod(directory, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(directory, "control.db")
	cfg := store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: time.Now}
	if runtime.GOOS != "linux" {
		cfg.Filesystem = notificationWorkflowFS{}
	}
	s, e := store.Open(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	db, e := sql.Open("sqlite3", path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	exec := func(q string, a ...any) {
		t.Helper()
		if _, e := db.Exec(q, a...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`UPDATE system_meta SET state_revision=1 WHERE id=1`)
	exec(`INSERT INTO effective_authorization_principals VALUES('operator-a','human','active',1,'now','now')`)
	exec(`INSERT INTO operator_devices VALUES('device-a','operator-a','approved',1,'now','now')`)
	exec(`INSERT INTO read_principals VALUES('operator-a','active',1,'now','now')`)
	grant := func(cap, kind, id, action string) {
		t.Helper()
		exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','infrastructure-admin',?,?,?,?,NULL,1,'active','now','now')`, "grant-"+ingress.Digest([]string{cap, id})[7:28], action, cap, kind, id)
	}
	grant("network.ingress.prepare", "ingress-profile", "bootstrap", "author")
	grant("network.ingress.read", "ingress-profile", "bootstrap", "read")
	exec(`INSERT INTO read_grants VALUES('operator-a','network.ingress.read','ingress-profile','bootstrap',1,'active','now','now')`)
	activated := time.Now().UTC().Format(time.RFC3339)
	for _, x := range []struct{ id, purpose string }{{"ingress-read", ingress.PurposeRead}, {"ingress-write", ingress.PurposeWrite}, {"ingress-replacement", ingress.PurposeReplacement}} {
		exec(`INSERT INTO credential_reference_versions VALUES(?,?,?,?,'bootstrap','fixture-ingress','one',?,'active',1,0,?,?,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, x.id+"-version", x.id, ingress.AdapterID, x.purpose, ingress.Digest(x.id), activated, []byte(`["cloudflare.ingress"]`), ingress.Digest("fixture-plan"))
	}

	sdk := &ingressBootstrapAcceptanceBackend{}
	c := generated.IngressChange{Schema: generated.SchemaIDIngressChange, SchemaVersion: "1.0.0", ProfileID: "bootstrap", AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), Action: "bootstrap-tunnel", ResourceKind: "tunnel-configuration", OwnerID: "operator-a", DeviceID: "device-a", BeforeDigest: ingress.Digest("before"), Hostname: "console.example.test", OriginService: "https://10.0.0.7:8443", OriginServerName: "console.example.test", OriginIdentityDigest: ingress.Digest("leaf"), DNSRecordID: strings.Repeat("c", 32), PolicyName: "console-bootstrap", AllowedGroupIDs: []string{}, Connectors: []generated.IngressConnectorTarget{{Schema: generated.SchemaIDIngressConnectorTarget, SchemaVersion: "1.0.0", HostID: "controller-a", IdentityDigest: ingress.Digest("controller")}}, ObservationReferenceID: "ingress-read", MutationReferenceID: "ingress-write", ReplacementReferenceID: "ingress-replacement", Bootstrap: &generated.IngressBootstrap{Schema: generated.SchemaIDIngressBootstrap, SchemaVersion: "1.0.0", Name: "console-bootstrap", AllowedEmail: "operator@example.test", SourceRunIDs: []string{}}}
	repo := store.NewIngressRepository(s, []string{ingress.ScopeDigest(c)})
	revisions := store.NewPlanRepository(s)
	decl, e := change.NewService(store.NewDeclarationRepository(s), time.Now)
	if e != nil {
		t.Fatal(e)
	}
	observations, e := planengine.NewStateObservationReader(revisions)
	if e != nil {
		t.Fatal(e)
	}
	plans, e := planengine.NewService(planengine.Config{IngressChanges: repo, Repository: revisions, Observations: observations, Clock: time.Now, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if e != nil {
		t.Fatal(e)
	}
	n := 0
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { n++; return fmt.Sprintf("ingress-request-%d", n), nil })
	app, e := api.NewApplication(api.Config{Authority: s, Authorizer: store.NewReadAuthorizer(s), Reads: store.NewReadRepository(s), Results: factory})
	if e != nil {
		t.Fatal(e)
	}
	policy := store.NewEffectiveAuthorizationRepository(s)
	if e = api.RegisterDeclarationPlanOperations(app, api.DeclarationPlanConfig{Declarations: decl, Plans: plans, Results: factory, Authorization: api.EffectiveAuthorizationConfig{Authorizer: authorization.NewEvaluator(policy), Recorder: policy, Clock: time.Now}}); e != nil {
		t.Fatal(e)
	}
	refs := store.NewCredentialRepository(s)
	if e = api.RegisterIngressOperations(app, api.IngressOperations{Repository: repo, Declarations: decl, Credentials: refs, Results: factory, Observe: func(ctx context.Context, q generated.IngressDraftRequest) (generated.IngressStatusData, error) {
		d, e := repo.Preview(ctx, q)
		if e != nil {
			return generated.IngressStatusData{}, e
		}
		v, _ := ingressAcceptanceResolver{}.Resolve(ctx, d.Bindings[0])
		defer v.Close()
		o, e := sdk.ObserveBootstrap(ctx, q.Change, v)
		return generated.IngressStatusData{Schema: generated.SchemaIDIngressStatusData, SchemaVersion: "1.0.0", ProfileID: q.Change.ProfileID, RotationStage: "not-requested", Connectivity: "unknown", OriginIsolation: "unknown", Status: "observed", Reason: o.Reason, ObservationDigest: o.Digest, ObservedAt: time.Now().UTC().Format(time.RFC3339), StateRevision: q.ExpectedStateRevision, RecoveryEpoch: q.RecoveryEpoch}, e
	}}); e != nil {
		t.Fatal(e)
	}
	principal := identity.Principal{ID: "operator-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman, DeviceID: "device-a"}
	ctx = identity.WithVerifiedPrincipal(ctx, principal)
	request := func(method, path string, input any) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(input)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw)).WithContext(ctx)
		if input != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		return w
	}
	decode := func(w *httptest.ResponseRecorder, out any) {
		t.Helper()
		if w.Code != 200 {
			t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
		}
		var env struct {
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(w.Body.Bytes(), &env) != nil || json.Unmarshal(env.Data, out) != nil {
			t.Fatal(w.Body.String())
		}
	}
	registry := adapter.NewRegistry()
	if e = registry.Register(ingress.AdapterID, &cloud.IngressAdapter{Authority: ingressBootstrapAcceptanceAuthority{ingressAcceptanceAuthority{repository: repo, t: t}}, Backend: sdk}); e != nil {
		t.Fatal(e)
	}
	if e = registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "fixture-ingress", ConsumerID: ingress.AdapterID, ProfileID: "synthetic-profile", CapabilityID: "credential.ingress.read", Enabled: true}, ingressAcceptanceResolver{}); e != nil {
		t.Fatal(e)
	}

	// Production setup authority must reject fixture custody before the executor
	// may resolve a credential. The positive engine below substitutes that native
	// boundary explicitly; it does not claim systemd custody qualification.
	caps, _ := json.Marshal([]string{"cloudflare.ingress", "credential.ingress.read", ingress.BootstrapCapability})
	exec(`INSERT INTO gate_applied_profiles VALUES('bootstrap-profile','vegastack-labs','1.0.0','bootstrap-policy','1.0.0',?,1,0,'fixture-profile',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, caps, ingress.Digest("fixture-plan"))
	authorityState, e := s.CurrentAuthority(ctx)
	if e != nil {
		t.Fatal(e)
	}
	bootstrapPolicy := generated.IngressBootstrapPolicy{Change: c, ControllerHostID: c.Connectors[0].HostID, ControllerIdentityDigest: c.Connectors[0].IdentityDigest, ControllerInstanceID: authorityState.InstanceID, ControllerMachineIDDigest: ingress.Digest("machine")}
	recoverySocket := filepath.Join(directory, "recovery.sock")
	listener, e := net.Listen("unix", recoverySocket)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	production := &ingressAuthority{repository: repo, gates: store.NewGateRepository(s), credentials: refs, registry: registry}
	production.bootstrap = &ingressBootstrapComposition{profile: serverconfig.Profile{SocketPath: recoverySocket, IngressBootstrap: &bootstrapPolicy}, store: s, source: production, machine: func() (string, error) { return ingress.Digest("machine"), nil }}
	runs := map[string]string{}
	ids := map[string]string{}
	for stage, action := range ingress.BootstrapActions {
		c.Action = action
		c.ResourceKind = ingress.BootstrapKind(action)
		c.Bootstrap.SourceRunIDs = []string{}
		for _, need := range ingress.BootstrapNeeds(action) {
			c.Bootstrap.SourceRunIDs = append(c.Bootstrap.SourceRunIDs, runs[need])
		}
		c.TunnelID = ""
		c.AccessAppID = ""
		c.AccessPolicyID = ""
		c.AllowedGroupIDs = []string{}
		if stage >= 3 {
			c.AccessAppID = ids["bootstrap-app"]
			c.AllowedGroupIDs = []string{ids["bootstrap-group"]}
		}
		if stage >= 4 {
			c.TunnelID = ids["bootstrap-tunnel"]
			c.AccessPolicyID = ids["bootstrap-policy"]
		}
		if action == "bootstrap-cutover" {
			c.Connectors[0].ConnectorID = "55555555-5555-4555-8555-555555555555"
		}
		current, e := revisions.CurrentRevision(ctx)
		if e != nil {
			t.Fatal(e)
		}
		q := generated.IngressDraftRequest{Schema: generated.SchemaIDIngressDraftRequest, SchemaVersion: "1.0.0", Change: c, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: fmt.Sprintf("ingress-stage-%d", stage)}
		var observed generated.IngressStatusData
		decode(request("POST", "/api/v1/network/ingress/observe", q), &observed)
		q.Change.BeforeDigest = observed.ObservationDigest
		id := "ingress-" + ingress.Digest(q)[7:39]
		grant("declaration.author", "declaration", id, "author")
		var submission generated.IngressDraftSubmission
		decode(request("POST", "/api/v1/network/ingress/draft", q), &submission)
		if sdk.writes != stage {
			t.Fatal("inert draft mutated provider")
		}

		if stage == 0 {
			historical := q
			historical.ExpectedStateRevision = 0
			historyRaw, _ := json.Marshal(historical)
			exec(`INSERT INTO ingress_drafts SELECT 'historical-draft',?, ?,bindings_bytes,actor_id,actor_method,actor_device,recovery_epoch FROM ingress_drafts WHERE draft_id=?`, ingress.Digest(historical), historyRaw, submission.DraftID)
			exec(`INSERT INTO ingress_observations VALUES('historical-observation','bootstrap','historical-draft','historical-run','observed','historical-state',?,'2000-01-01T00:00:00Z',0)`, ingress.Digest("historical-observation"))
		}
		stored, e := store.NewDeclarationRepository(s).GetRevision(ctx, submission.DeclarationID, 1)
		if e != nil {
			t.Fatal(e)
		}
		fingerprint, e := observations.CurrentFingerprint(ctx, stored.DeclarationID, stored.Operations)
		if e != nil {
			t.Fatal(e)
		}
		planned, e := plans.Create(ctx, planengine.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: "ingress-fixture-session"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: stored.DeclarationID, DeclarationRevision: 1, ExpectedStateRevision: submission.StateRevision, RecoveryEpoch: submission.RecoveryEpoch, ObservationFingerprint: fingerprint, IdempotencyKey: fmt.Sprintf("ingress-plan-%d", stage), Extensions: stored.Extensions})
		if e != nil {
			t.Fatal(e)
		}

		if stage == 0 {
			op := planned.Plan.Operations[0]
			if e := (ingressSecretGate{source: production}).VerifySecretStep(ctx, planned.Plan, op); e == nil {
				t.Fatal("production native-custody gate accepted fixture resolver")
			}
			if sdk.writes != 0 {
				t.Fatal("failed custody reached provider mutation")
			}
		}
		p := planned.Plan
		ack, e := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(s), Plans: lifecycleAcceptancePlanReader{plans}, Authorizer: lifecycleAcceptanceAuthorizer{}, Clock: time.Now})
		if e != nil {
			t.Fatal(e)
		}
		human := identity.Principal{ID: "human-a", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
		card, e := ack.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: fmt.Sprintf("ingress-nonce-%d", stage)}, p.PlanID)
		if e != nil {
			t.Fatal(e)
		}
		approved, e := ack.Decide(ctx, acknowledgement.Candidate{Human: human, AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove, PlanID: p.PlanID, PlanDigest: p.PlanDigest, TargetDigest: p.Binding.TargetDigest, ReasonDigest: p.Binding.ReasonDigest, Nonce: card.Nonce, StateRevision: p.Binding.StateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch, ExpiresAt: mustAcceptanceTime(t, p.ExpiresAt), DecidedAt: time.Now()})
		if e != nil {
			t.Fatal(e)
		}
		engine, e := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(s), Plans: plans, Admission: runengine.NewAdmissionGate(ack, time.Now), Adapters: registry, SecretGate: ingressAcceptanceGate{}, CredentialStep: &runengine.CredentialStep{Bindings: refs, Resolvers: registry, Profiles: ingressAcceptanceProfile{}, Plans: plans, Clock: time.Now}, Clock: time.Now})
		if e != nil {
			t.Fatal(e)
		}
		branch := "human"
		decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: fmt.Sprintf("ingress-decision-%d", stage), PrincipalID: principal.ID, Action: "execute", TargetID: c.ProfileID, Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, PlanDigest: p.PlanDigest, DecidedAt: time.Now().UTC().Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
		submissionToRun := runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, IdempotencyKey: fmt.Sprintf("ingress-run-%d", stage), Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: audit.Attribution{AuthenticatedPrincipalID: principal.ID, AuthenticatedPrincipalMethod: principal.Method, ResponsibleHumanPrincipalID: &human.ID}}
		if stage == 0 {
			noAck := submissionToRun
			noAck.Acknowledgement = nil
			if _, e := engine.Submit(ctx, noAck); e == nil || sdk.writes != 0 {
				t.Fatal("unacknowledged import executed")
			}
		}

		applied, e := engine.Submit(ctx, submissionToRun)
		if e != nil || applied.Status != "succeeded" {
			t.Fatalf("stage %s: %+v %v", action, applied, e)
		}
		var status generated.IngressStatusData
		decode(request("GET", "/api/v1/network/ingress/bootstrap", nil), &status)
		if status.ResourceID == "" || status.RunID == "" || status.Status != "observed" {
			t.Fatalf("missing durable receipt %+v", status)
		}

		oldDraft, e := repo.GetStaged(ctx, submission.DraftID)
		if e != nil {
			t.Fatal(e)
		}
		var oldStep string
		if e = db.QueryRow(`SELECT step_id FROM plan_run_steps WHERE run_id=?`, status.RunID).Scan(&oldStep); e != nil {
			t.Fatal(e)
		}
		if e = repo.ReserveBootstrap(ctx, oldDraft, adapter.ExactExecutionBinding{RunID: status.RunID, StepID: oldStep}, ingress.Snapshot{}); e == nil {
			t.Fatal("completed run replay reserved a second provider write")
		}
		ids[action] = status.ResourceID
		runs[action] = status.RunID
		if sdk.writes != stage+1 || (action != "bootstrap-cutover" && sdk.dnsWrites != 0) {
			t.Fatal("wrong effect count or early DNS publication")
		}
		// Reusing a fresh key must not create this resource again.
		current, _ = revisions.CurrentRevision(ctx)
		q.ExpectedStateRevision = current.StateRevision
		q.IdempotencyKey = fmt.Sprintf("duplicate-stage-%d", stage)
		if w := request("POST", "/api/v1/network/ingress/draft", q); w.Code == 200 {
			t.Fatal("completed resource stage accepted again")
		}
	}

	current, _ := revisions.CurrentRevision(ctx)
	later := generated.IngressDraftRequest{Schema: generated.SchemaIDIngressDraftRequest, SchemaVersion: "1.0.0", Change: c, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: "later-owned-observation"}
	later.Change.Bootstrap = nil
	later.Change.Action = "import"
	later.Change.ResourceKind = "tunnel-configuration"
	later.Change.ResourceID = later.Change.TunnelID
	laterRaw, _ := json.Marshal(later)
	exec(`INSERT INTO ingress_drafts SELECT 'later-owned-draft',?, ?,bindings_bytes,actor_id,actor_method,actor_device,recovery_epoch FROM ingress_drafts WHERE draft_id='historical-draft'`, ingress.Digest(later), laterRaw)
	exec(`INSERT INTO ingress_observations VALUES('later-owned-observation','bootstrap','later-owned-draft','later-owned-run','observed','owned-route-observed',?,?,0)`, ingress.Digest("later-owned-observation"), time.Now().UTC().Format(time.RFC3339))
	var laterStatus generated.IngressStatusData
	decode(request("GET", "/api/v1/network/ingress/bootstrap", nil), &laterStatus)
	if laterStatus.Status != "observed" || laterStatus.Reason != "owned-route-observed" || laterStatus.ObservationDigest != ingress.Digest("later-owned-observation") || laterStatus.RunID != "" || laterStatus.ResourceID != "" {
		t.Fatalf("later ordinary observation lost or mixed with old bootstrap %+v", laterStatus)
	}
	if sdk.dnsWrites != 1 {
		t.Fatal("cutover did not name exactly one existing DNS record")
	}
}
