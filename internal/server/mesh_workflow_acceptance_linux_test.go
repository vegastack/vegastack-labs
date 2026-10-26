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
	mesh "github.com/vegastack/vegastack-labs/internal/networkmesh"
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

type meshAcceptanceResolver struct{}

func (meshAcceptanceResolver) Resolve(_ context.Context, b credentialref.StepBinding) (*credentialref.Value, error) {
	if b.PurposeID == mesh.PurposeRead {
		return credentialref.NewValue([]byte("fixture-observer"))
	}
	return credentialref.NewValue([]byte("fixture-mutator"))
}

type meshAcceptanceProfile struct{}

func (meshAcceptanceProfile) GetAppliedProfileScope(context.Context) (store.GateAppliedProfile, error) {
	return store.GateAppliedProfile{ProfileID: "synthetic-profile", Capabilities: []string{"credential.mesh.read"}}, nil
}

// Fixtures qualify only the engine seam. Production retains its actual evaluator/native resolver.
type meshAcceptanceGate struct{}

func (meshAcceptanceGate) VerifySecretStep(context.Context, generated.Plan, generated.PlanOperation) error {
	return nil
}

type meshAcceptanceAuthority struct{ repository *store.MeshRepository }

func (a meshAcceptanceAuthority) Resolve(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding) (mesh.Staged, error) {
	return a.repository.Resolve(ctx, op, b)
}
func (a meshAcceptanceAuthority) BorrowRead(context.Context, mesh.Staged) (*credentialref.Value, error) {
	return credentialref.NewValue([]byte("fixture-observer"))
}
func (a meshAcceptanceAuthority) Record(ctx context.Context, d mesh.Staged, b adapter.ExactExecutionBinding, s mesh.Snapshot, status string) error {
	return a.repository.Record(ctx, d, b, s, status)
}

type meshRewriteTransport struct {
	base *url.URL
	next http.RoundTripper
}

func (t meshRewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	q := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = t.base.Scheme
	u.Host = t.base.Host
	q.URL = &u
	return t.next.RoundTrip(q)
}
func TestMeshAcceptanceAPIImportApprovedApplyAndOwnedUpdate(t *testing.T) {
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
		exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','infrastructure-admin',?,?,?,?,NULL,1,'active','now','now')`, "grant-"+mesh.Digest([]string{cap, id})[7:28], action, cap, kind, id)
	}
	grant("network.mesh.prepare", "mesh-profile", "pilot", "author")
	grant("network.mesh.read", "mesh-profile", "pilot", "read")
	exec(`INSERT INTO read_grants VALUES('operator-a','network.mesh.read','mesh-profile','pilot',1,'active','now','now')`)
	activated := time.Now().UTC().Format(time.RFC3339)
	for _, x := range []struct{ id, purpose string }{{"mesh-read", mesh.PurposeRead}, {"mesh-write", mesh.PurposeWrite}} {
		exec(`INSERT INTO credential_reference_versions VALUES(?,?,?,?,'pilot','fixture-mesh','one',?,'active',1,0,?,?,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, x.id+"-version", x.id, mesh.AdapterID, x.purpose, mesh.Digest(x.id), activated, []byte(`["cloudflare.mesh"]`), mesh.Digest("fixture-plan"))
	}
	writes := 0
	routes := []map[string]string{{"address": "10.0.0.0/24"}}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasSuffix(r.URL.Path, "/include") {
			t.Errorf("unexpected provider path %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		if r.Method == "PUT" {
			writes++
			if r.Header.Get("Authorization") != "Bearer fixture-mutator" {
				t.Error("wrong mutation credential")
			}
			if e := json.NewDecoder(r.Body).Decode(&routes); e != nil {
				t.Error(e)
			}
		} else if r.Header.Get("Authorization") != "Bearer fixture-observer" {
			t.Error("wrong observation credential")
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": routes})
	}))
	defer provider.Close()
	base, _ := url.Parse(provider.URL)
	sdk := cloud.NewClientWithTransport(meshRewriteTransport{base, provider.Client().Transport})
	c := generated.MeshChange{Schema: generated.SchemaIDMeshChange, SchemaVersion: "1.0.0", Mode: "foundation", ProfileID: "pilot", AccountID: strings.Repeat("a", 32), Action: "import", ResourceKind: "profile-include", ResourceID: "11111111-1111-4111-8111-111111111111", OwnerID: "operator-a", DeviceID: "device-a", PhysicalDeviceID: "none", ProviderUserID: "none", BeforeDigest: mesh.Digest(nil), Routes: []generated.MeshRoute{}, AffectedIdentityDigests: []string{mesh.Digest("synthetic-eligible-host")}, MeshCIDR: "100.96.0.0/12", RuleName: "unused", RuleAction: "block", Traffic: "unused", RuleIdentity: "unused", ObservationReferenceID: "mesh-read", MutationReferenceID: "mesh-write"}
	repo := store.NewMeshRepository(s, []string{mesh.ScopeDigest(c)})
	revisions := store.NewPlanRepository(s)
	decl, e := change.NewService(store.NewDeclarationRepository(s), time.Now)
	if e != nil {
		t.Fatal(e)
	}
	observations, e := planengine.NewStateObservationReader(revisions)
	if e != nil {
		t.Fatal(e)
	}
	plans, e := planengine.NewService(planengine.Config{MeshChanges: repo, Repository: revisions, Observations: observations, Clock: time.Now, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if e != nil {
		t.Fatal(e)
	}
	n := 0
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { n++; return fmt.Sprintf("mesh-request-%d", n), nil })
	app, e := api.NewApplication(api.Config{Authority: s, Authorizer: store.NewReadAuthorizer(s), Reads: store.NewReadRepository(s), Results: factory})
	if e != nil {
		t.Fatal(e)
	}
	policy := store.NewEffectiveAuthorizationRepository(s)
	if e = api.RegisterDeclarationPlanOperations(app, api.DeclarationPlanConfig{Declarations: decl, Plans: plans, Results: factory, Authorization: api.EffectiveAuthorizationConfig{Authorizer: authorization.NewEvaluator(policy), Recorder: policy, Clock: time.Now}}); e != nil {
		t.Fatal(e)
	}
	refs := store.NewCredentialRepository(s)
	if e = api.RegisterMeshOperations(app, api.MeshOperations{Repository: repo, Declarations: decl, Credentials: refs, Results: factory, Observe: func(ctx context.Context, q generated.MeshDraftRequest) (generated.MeshStatusData, error) {
		d, e := repo.Preview(ctx, q)
		if e != nil {
			return generated.MeshStatusData{}, e
		}
		v, _ := meshAcceptanceResolver{}.Resolve(ctx, d.Bindings[0])
		defer v.Close()
		o, e := sdk.Observe(ctx, q.Change, v)
		return generated.MeshStatusData{Schema: generated.SchemaIDMeshStatusData, SchemaVersion: "1.0.0", ProfileID: q.Change.ProfileID, Status: "observed", Reason: o.Reason, ObservationDigest: o.Digest, ObservedAt: time.Now().UTC().Format(time.RFC3339), StateRevision: q.ExpectedStateRevision, RecoveryEpoch: q.RecoveryEpoch}, e
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
	if e = registry.Register(mesh.AdapterID, &cloud.MeshAdapter{Authority: meshAcceptanceAuthority{repo}, Backend: sdk}); e != nil {
		t.Fatal(e)
	}
	if e = registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "fixture-mesh", ConsumerID: mesh.AdapterID, ProfileID: "synthetic-profile", CapabilityID: "credential.mesh.read", Enabled: true}, meshAcceptanceResolver{}); e != nil {
		t.Fatal(e)
	}
	for stage := 0; stage < 2; stage++ {
		current, e := revisions.CurrentRevision(ctx)
		if e != nil {
			t.Fatal(e)
		}
		q := generated.MeshDraftRequest{Schema: generated.SchemaIDMeshDraftRequest, SchemaVersion: "1.0.0", Change: c, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: fmt.Sprintf("mesh-stage-%d", stage)}
		var observed generated.MeshStatusData
		decode(request("POST", "/api/v1/network/mesh/observe", q), &observed)
		q.Change.BeforeDigest = observed.ObservationDigest
		id := "mesh-" + mesh.Digest(q)[7:39]
		grant("declaration.author", "declaration", id, "author")
		var submission generated.MeshDraftSubmission
		decode(request("POST", "/api/v1/network/mesh/draft", q), &submission)
		if writes != 0 {
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
		planned, e := plans.Create(ctx, planengine.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: stored.DeclarationID, DeclarationRevision: 1, ExpectedStateRevision: submission.StateRevision, RecoveryEpoch: submission.RecoveryEpoch, ObservationFingerprint: fingerprint, IdempotencyKey: fmt.Sprintf("mesh-plan-%d", stage), Extensions: stored.Extensions})
		if e != nil {
			t.Fatal(e)
		}
		p := planned.Plan
		ack, e := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(s), Plans: lifecycleAcceptancePlanReader{plans}, Authorizer: lifecycleAcceptanceAuthorizer{}, Clock: time.Now})
		if e != nil {
			t.Fatal(e)
		}
		human := identity.Principal{ID: "human-a", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
		card, e := ack.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: fmt.Sprintf("mesh-nonce-%d", stage)}, p.PlanID)
		if e != nil {
			t.Fatal(e)
		}
		approved, e := ack.Decide(ctx, acknowledgement.Candidate{Human: human, AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove, PlanID: p.PlanID, PlanDigest: p.PlanDigest, TargetDigest: p.Binding.TargetDigest, ReasonDigest: p.Binding.ReasonDigest, Nonce: card.Nonce, StateRevision: p.Binding.StateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch, ExpiresAt: mustAcceptanceTime(t, p.ExpiresAt), DecidedAt: time.Now()})
		if e != nil {
			t.Fatal(e)
		}
		engine, e := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(s), Plans: plans, Admission: runengine.NewAdmissionGate(ack, time.Now), Adapters: registry, SecretGate: meshAcceptanceGate{}, CredentialStep: &runengine.CredentialStep{Bindings: refs, Resolvers: registry, Profiles: meshAcceptanceProfile{}, Plans: plans, Clock: time.Now}, Clock: time.Now})
		if e != nil {
			t.Fatal(e)
		}
		branch := "human"
		decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: fmt.Sprintf("mesh-decision-%d", stage), PrincipalID: principal.ID, Action: "execute", TargetID: c.ProfileID, Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, PlanDigest: p.PlanDigest, DecidedAt: time.Now().UTC().Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
		applied, e := engine.Submit(ctx, runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, IdempotencyKey: fmt.Sprintf("mesh-run-%d", stage), Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: audit.Attribution{AuthenticatedPrincipalID: principal.ID, AuthenticatedPrincipalMethod: principal.Method, ResponsibleHumanPrincipalID: &human.ID}})
		if e != nil || applied.Status != "succeeded" {
			t.Fatalf("Mesh apply stage %d: %+v %v", stage, applied, e)
		}
		c.Action = "profile-routing-update"
		c.ExpectedOwnershipRevision = 1
		c.Routes = []generated.MeshRoute{{Schema: generated.SchemaIDMeshRoute, SchemaVersion: "1.0.0", Address: "10.0.0.0/24"}, {Schema: generated.SchemaIDMeshRoute, SchemaVersion: "1.0.0", Address: "100.96.0.0/12"}}
	}
	if writes != 1 {
		t.Fatalf("import/update provider writes %d", writes)
	}
	var status generated.MeshStatusData
	decode(request("GET", "/api/v1/network/mesh/pilot", nil), &status)
	if status.OwnershipRevision != 2 || status.Status != "observed" {
		t.Fatalf("wrong ownership/status %+v", status)
	}
	exec(`UPDATE operator_devices SET status='revoked',device_revision=2 WHERE device_id='device-a'`)
	if w := request("GET", "/api/v1/network/mesh/pilot", nil); w.Code == 200 {
		t.Fatal("revoked device retained Mesh read")
	}
}
