//go:build linux

package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
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
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type ingressAcceptanceResolver struct{}

func (ingressAcceptanceResolver) Resolve(_ context.Context, b credentialref.StepBinding) (*credentialref.Value, error) {
	if b.PurposeID == ingress.PurposeReplacement {
		return credentialref.NewValue([]byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("s"), 32))))
	}
	if b.PurposeID == ingress.PurposeRead {
		return credentialref.NewValue([]byte("fixture-observer"))
	}
	return credentialref.NewValue([]byte("fixture-mutator"))
}

type ingressAcceptanceProfile struct{}

func (ingressAcceptanceProfile) GetAppliedProfileScope(context.Context) (store.GateAppliedProfile, error) {
	return store.GateAppliedProfile{ProfileID: "synthetic-profile", Capabilities: []string{"credential.ingress.read"}}, nil
}

// Fixtures qualify only the engine seam. Production retains its actual evaluator/native resolver.
type ingressAcceptanceGate struct{}

func (ingressAcceptanceGate) VerifySecretStep(context.Context, generated.Plan, generated.PlanOperation) error {
	return nil
}

type ingressAcceptanceAuthority struct {
	repository *store.IngressRepository
	t          *testing.T
}

func (a ingressAcceptanceAuthority) Resolve(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding) (ingress.Staged, error) {
	d, e := a.repository.Resolve(ctx, op, b)
	if e != nil {
		a.t.Logf("Ingress bound authority denied: %T %v", e, e)
	}
	return d, e
}
func (a ingressAcceptanceAuthority) BorrowRead(context.Context, ingress.Staged) (*credentialref.Value, error) {
	return credentialref.NewValue([]byte("fixture-observer"))
}
func (a ingressAcceptanceAuthority) Record(ctx context.Context, d ingress.Staged, b adapter.ExactExecutionBinding, s ingress.Snapshot, status string) error {
	e := a.repository.Record(ctx, d, b, s, status)
	if e != nil {
		a.t.Logf("Ingress observation record denied: %T %v", e, e)
	}
	return e
}

type ingressRewriteTransport struct {
	base *url.URL
	next http.RoundTripper
}

func (t ingressRewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	q := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = t.base.Scheme
	u.Host = t.base.Host
	q.URL = &u
	return t.next.RoundTrip(q)
}
func TestIngressAcceptanceAPIImportApprovedApplyAndOwnedChanges(t *testing.T) {
	for _, action := range []string{"dns-record-update", "tunnel-config-update", "access-policy-update", "connector-disconnect", "token-rotate"} {
		t.Run(action, func(t *testing.T) { ingressAcceptanceOwnedChange(t, action) })
	}
}
func ingressAcceptanceOwnedChange(t *testing.T, action string) {
	ctx := context.Background()
	directory := t.TempDir()
	if e := os.Chmod(directory, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(directory, "control.db")
	s, e := store.Open(ctx, store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: time.Now})
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
	grant("network.ingress.prepare", "ingress-profile", "pilot", "author")
	grant("network.ingress.read", "ingress-profile", "pilot", "read")
	exec(`INSERT INTO read_grants VALUES('operator-a','network.ingress.read','ingress-profile','pilot',1,'active','now','now')`)
	activated := time.Now().UTC().Format(time.RFC3339)
	for _, x := range []struct{ id, purpose string }{{"ingress-read", ingress.PurposeRead}, {"ingress-write", ingress.PurposeWrite}, {"ingress-replacement", ingress.PurposeReplacement}} {
		exec(`INSERT INTO credential_reference_versions VALUES(?,?,?,?,'pilot','fixture-ingress','one',?,'active',1,0,?,?,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, x.id+"-version", x.id, ingress.AdapterID, x.purpose, ingress.Digest(x.id), activated, []byte(`["cloudflare.ingress"]`), ingress.Digest("fixture-plan"))
	}
	writes := 0
	const tunnelID = "11111111-1111-4111-8111-111111111111"
	const appID = "22222222-2222-4222-8222-222222222222"
	const policyID = "33333333-3333-4333-8333-333333333333"
	const connectorID = "44444444-4444-4444-8444-444444444444"
	dnsContent := tunnelID + ".cfargotunnel.com"
	if action == "dns-record-update" {
		dnsContent = "previous-target.invalid"
	}
	connected := true
	config := map[string]any{"ingress": []any{map[string]any{"hostname": "synthetic.ingress.invalid", "service": "https://10.10.0.11:443"}, map[string]any{"service": "http_status:404"}}}
	policyBody := map[string]any{"id": policyID, "name": "old-policy", "decision": "allow", "precedence": 1, "include": []any{map[string]any{"group": map[string]any{"id": policyID}}}}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		result := any(nil)
		if r.Method != "GET" {
			writes++
			if r.Header.Get("Authorization") != "Bearer fixture-mutator" {
				t.Error("wrong mutation credential")
			}
		} else if r.Header.Get("Authorization") != "Bearer fixture-observer" {
			t.Error("wrong observer credential")
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/connections"):
			if r.Method == "DELETE" {
				if r.URL.Query().Get("client_id") != connectorID {
					t.Error("unscoped connector disconnect")
				}
				connected = false
			} else if connected {
				result = []any{map[string]any{"id": connectorID, "conns": []any{map[string]any{"id": "55555555-5555-4555-8555-555555555555", "client_id": connectorID, "opened_at": "2026-01-01T00:00:00Z", "is_pending_reconnect": false}}}}
			} else {
				result = []any{}
			}
		case strings.Contains(r.URL.Path, "/dns_records/"):
			if r.Method == "PUT" {
				var body map[string]any
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("invalid DNS body")
				}
				dnsContent, _ = body["content"].(string)
			}
			result = map[string]any{"id": strings.Repeat("c", 32), "name": "synthetic.ingress.invalid", "type": "CNAME", "content": dnsContent, "proxied": true, "ttl": 1}
		case strings.HasSuffix(r.URL.Path, "/configurations"):
			if r.Method == "PUT" {
				var body struct {
					Config map[string]any `json:"config"`
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("invalid config body")
				}
				config = body.Config
			}
			result = map[string]any{"tunnel_id": tunnelID, "source": "cloudflare", "config": config}
		case strings.Contains(r.URL.Path, "/policies/"):
			if r.Method == "PUT" {
				if json.NewDecoder(r.Body).Decode(&policyBody) != nil {
					t.Error("invalid policy body")
				}
				policyBody["id"] = policyID
			}
			result = policyBody
		case strings.HasSuffix(r.URL.Path, "/apps/"+appID):
			result = map[string]any{"id": appID, "domain": "synthetic.ingress.invalid"}
		case strings.HasSuffix(r.URL.Path, "/"+tunnelID):
			if r.Method == "PATCH" {
				var body map[string]any
				if json.NewDecoder(r.Body).Decode(&body) != nil || body["tunnel_secret"] == nil {
					t.Error("missing bound replacement secret")
				}
			}
			result = map[string]any{"id": tunnelID}
		default:
			t.Errorf("unexpected provider path %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	}))

	defer provider.Close()
	base, _ := url.Parse(provider.URL)
	sdk := cloud.NewClientWithTransport(ingressRewriteTransport{base, provider.Client().Transport})
	c := generated.IngressChange{Schema: generated.SchemaIDIngressChange, SchemaVersion: "1.0.0", ProfileID: "pilot", AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), TunnelID: "11111111-1111-4111-8111-111111111111", Action: "import", ResourceKind: "dns-record", ResourceID: strings.Repeat("c", 32), OwnerID: "operator-a", DeviceID: "device-a", BeforeDigest: ingress.Digest(nil), Hostname: "synthetic.ingress.invalid", OriginService: "https://10.10.0.10:443", OriginServerName: "synthetic.origin.invalid", OriginIdentityDigest: ingress.Digest("synthetic-origin"), AccessAppID: "22222222-2222-4222-8222-222222222222", AccessPolicyID: "33333333-3333-4333-8333-333333333333", DNSRecordID: strings.Repeat("c", 32), ConnectorID: "unused", PolicyName: "synthetic", AllowedGroupIDs: []string{}, Connectors: []generated.IngressConnectorTarget{{Schema: generated.SchemaIDIngressConnectorTarget, SchemaVersion: "1.0.0", ConnectorID: "44444444-4444-4444-8444-444444444444", HostID: "synthetic-connector", IdentityDigest: ingress.Digest("synthetic-connector")}}, ObservationReferenceID: "ingress-read", MutationReferenceID: "ingress-write", ReplacementReferenceID: "ingress-replacement"}

	switch action {
	case "tunnel-config-update":
		c.ResourceKind = "tunnel-configuration"
		c.ResourceID = c.TunnelID
	case "access-policy-update":
		c.ResourceKind = "access-policy"
		c.ResourceID = c.AccessPolicyID
		c.AllowedGroupIDs = []string{appID}
	case "connector-disconnect":
		c.ResourceKind = "connector"
		c.ResourceID = connectorID
		c.ConnectorID = connectorID
	case "token-rotate":
		c.ResourceKind = "tunnel-token"
		c.ResourceID = c.TunnelID
	}

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
		o, e := sdk.ObserveIngress(ctx, q.Change, v)
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
	if e = registry.Register(ingress.AdapterID, &cloud.IngressAdapter{Authority: ingressAcceptanceAuthority{repository: repo, t: t}, Backend: sdk}); e != nil {
		t.Fatal(e)
	}
	if e = registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "fixture-ingress", ConsumerID: ingress.AdapterID, ProfileID: "synthetic-profile", CapabilityID: "credential.ingress.read", Enabled: true}, ingressAcceptanceResolver{}); e != nil {
		t.Fatal(e)
	}
	for stage := 0; stage < 3; stage++ {
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
		expectedWrites := 0
		if stage == 2 {
			expectedWrites = 1
		}
		if writes != expectedWrites {
			t.Fatal("draft mutated provider")
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
			if _, e := engine.Submit(ctx, noAck); e == nil || writes != 0 {
				t.Fatal("unacknowledged import executed")
			}
		}
		if stage == 2 {
			var beforeRevocation generated.IngressStatusData
			decode(request("GET", "/api/v1/network/ingress/pilot", nil), &beforeRevocation)
			if beforeRevocation.OwnershipRevision != 2 {
				t.Fatal("unexpected ownership")
			}
			exec(`UPDATE operator_devices SET status='revoked',device_revision=2 WHERE device_id='device-a'`)
		}
		applied, e := engine.Submit(ctx, submissionToRun)
		if stage == 2 {
			if e == nil || applied.Status == "succeeded" || writes != 1 {
				t.Fatalf("revoked device executed: %+v %v writes=%d", applied, e, writes)
			}
			break
		}

		if action == "token-rotate" && stage == 1 {
			if applied.Status != "partial" || writes != 1 {
				t.Fatalf("rotation must remain partial: %+v %v writes=%d", applied, e, writes)
			}
			var status generated.IngressStatusData
			decode(request("GET", "/api/v1/network/ingress/pilot", nil), &status)
			if status.RotationStage != "connector-update-required" || status.OwnershipRevision != 1 {
				t.Fatalf("rotation lost partial state: %+v", status)
			}
			return
		}
		if e != nil || applied.Status != "succeeded" {
			t.Fatalf("Ingress apply stage %d: %+v %v", stage, applied, e)
		}
		if action == "connector-disconnect" && stage == 1 {
			exec(`UPDATE operator_devices SET status='revoked',device_revision=2 WHERE device_id='device-a'`)
			if w := request("GET", "/api/v1/network/ingress/pilot", nil); w.Code == 200 {
				t.Fatal("revoked device retained connector read")
			}
			return
		}
		c.Action = action
		c.ExpectedOwnershipRevision = int64(stage + 1)
	}
	if writes != 1 {
		t.Fatalf("import/update provider writes %d", writes)
	}
	var ownershipRows int
	if e := db.QueryRow(`SELECT COUNT(*) FROM ingress_ownership WHERE profile_id='pilot'`).Scan(&ownershipRows); e != nil || ownershipRows != 2 {
		t.Fatalf("unexpected ownership after denied apply %d %v", ownershipRows, e)
	}
	if w := request("GET", "/api/v1/network/ingress/pilot", nil); w.Code == 200 {
		t.Fatal("revoked device retained Ingress read")
	}
}
