//go:build linux

package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/coolify"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostinglifecycle"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPhase8CombinedSoftwareLifecycle(t *testing.T) {
	for _, fault := range []string{"none", "provider-outage", "unknown-effect", "author-revoked", "epoch-changed", "device-revoked"} {
		t.Run(fault, func(t *testing.T) { testHostingLifecycleAPI(t, fault) })
	}
}
func testHostingLifecycleAPI(t *testing.T, fault string) {
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	digest := hostaction.Digest("synthetic-grant-setup")
	human := "human-a"
	policyTarget := "hosting-a"
	db := filepath.Join(dir, "control.db")
	read := generated.LocalSetupReadGrant{Schema: generated.SchemaIDLocalSetupReadGrant, SchemaVersion: "1.0.0", Capability: "hosting.read", ResourceKind: "hosting", ResourceID: policyTarget}
	effective := []generated.LocalSetupEffectiveGrant{}
	for _, x := range []struct{ id, action, cap, kind, branch string }{{"hosting-read", "read", "hosting.read", "hosting", "none"}, {"hosting-author", "author", "hosting.lifecycle.prepare", "hosting", "none"}, {"hosting-execute", "execute", "hosting.lifecycle.apply", "execution-target", "human"}, {"hosting-ack", "acknowledge", "plan.acknowledge", "plan-target", "human"}} {
		effective = append(effective, generated.LocalSetupEffectiveGrant{Schema: generated.SchemaIDLocalSetupEffectiveGrant, SchemaVersion: "1.0.0", GrantID: x.id, RoleID: "control-plane-admin", Action: x.action, Capability: x.cap, ResourceKind: x.kind, ResourceID: policyTarget, Branch: x.branch})
	}
	request := generated.LocalSetupReviewRequest{Schema: generated.SchemaIDLocalSetupReviewRequest, SchemaVersion: "1.0.0", SetupID: "grant-setup", HostIdentityDigest: digest, InitialHumanID: human, ServiceUID: int64(os.Geteuid()), InitialAdministratorUID: int64(os.Geteuid()), ProfileSHA256: digest, DatabasePath: db, ReleaseManifestPath: "/synthetic/manifest.json", ReleaseManifestDigest: digest, ReleasePolicyPath: "/synthetic/policy.json", ReleasePolicyDigest: digest, ExecutableAssetID: "linux-arm64", ReleaseBuildID: "test", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), RequestNonceDigest: digest, InitialReadGrants: []generated.LocalSetupReadGrant{read}, InitialEffectiveGrants: effective}
	review := store.InitialSetupReview{Request: request, RequestDigest: digest, Acknowledgement: store.InitialAcknowledgementBinding{HumanID: human, AuthorityID: "fixture-authority", Method: identity.CloudflareAccessMethod, ProfileDigest: digest, ExternalScopeID: "scope/synthetic", ExternalSubjectID: "synthetic@example.test", DeliveryTargetID: "delivery/synthetic"}}
	raw, _ := json.Marshal(review)
	setup := store.InitialSetup{SetupID: request.SetupID, HumanID: human, ReviewJSON: raw, ReviewDigest: hostaction.BytesDigest(raw), RequestDigest: digest, ExpiresAt: now.Add(time.Hour), ReadGrants: []store.InitialReadGrant{{Capability: read.Capability, ResourceKind: read.ResourceKind, ResourceID: policyTarget}}}
	for _, g := range effective {
		branch := g.Branch
		if branch == "none" {
			branch = ""
		}
		setup.EffectiveGrants = append(setup.EffectiveGrants, store.InitialEffectiveGrant{GrantID: g.GrantID, RoleID: g.RoleID, Action: g.Action, Capability: g.Capability, ResourceKind: g.ResourceKind, ResourceID: g.ResourceID, Branch: branch})
	}
	setup.Approval = store.InitialSetupApproval{HumanID: human, AuthorityID: "fixture-authority", Method: identity.CloudflareAccessMethod, ReviewDigest: setup.ReviewDigest, RequestDigest: digest, DecidedAt: now.Add(-time.Minute)}

	profile := generated.HostingLifecycleProfile{Schema: generated.SchemaIDHostingLifecycleProfile, SchemaVersion: "1.0.0", BindingID: "binding-a", TargetID: policyTarget, ConfigurationPath: "/protected/profile", ConfigurationDigest: digest, MutationReferenceID: "hosting-admin", PlatformReferenceID: "platform-admin"}
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: db, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock, HostingLifecycleProfiles: []hostinglifecycle.Profile{{Binding: profile}}, InitialSetup: &setup})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	principal := identity.Principal{ID: human, Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	ctx := identity.WithVerifiedPrincipal(context.Background(), principal)
	repo := store.NewHostingLifecycleRepository(authority)
	providerReads, writes, callbacks := 0, 0, 0
	project, environment := false, false
	executing := false
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerReads++
		if executing && fault == "provider-outage" {
			w.WriteHeader(503)
			return
		}
		if r.Method != "GET" {
			writes++
		}
		var out any
		switch r.Method + " " + r.URL.Path {
		case "GET /team":
			out = map[string]any{"id": 1}
		case "GET /projects":
			out = []any{}
		case "POST /projects":
			project = true
			if fault == "unknown-effect" {
				w.WriteHeader(503)
				return
			}
			out = map[string]any{"uuid": "project-a"}
			w.WriteHeader(201)
		case "GET /projects/project-a":
			if !project {
				t.Error("uncreated provider object")
			}
			out = map[string]any{"id": 2, "uuid": "project-a", "name": "project", "team_id": 1}
		case "GET /projects/project-a/environments":
			out = []any{}
			if environment {
				out = []any{map[string]any{"id": 3, "name": "production", "project_id": 2}}
			}
		case "POST /projects/project-a/environments":
			environment = true
			out = map[string]any{"uuid": "environment-a"}
			w.WriteHeader(201)
		default:
			t.Errorf("unexpected provider %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(out)
	}))
	defer peer.Close()
	provider, _ := coolify.NewClient(peer.URL, peer.Client().Transport)
	secret, _ := credentialref.NewValue([]byte("fixture-private-provider-secret"))
	defer secret.Close()
	resourceRequest := func(check func() error) coolify.ResourceRequest {
		return coolify.ResourceRequest{TeamID: 1, ProjectName: "project", Environment: "production", Check: check}
	}
	prepare := func(ctx context.Context, d generated.HostingLifecycleDraftRequest) (generated.HostingLifecycleRequest, error) {
		q, e := repo.Prepare(ctx, d)
		if e != nil {
			return q, e
		}
		snapshot, e := provider.ObserveResources(ctx, resourceRequest(func() error { return repo.Authorize(ctx, q) }), secret)
		if e != nil {
			return q, e
		}
		q.ObservedDigest = hostinglifecycle.Digest(snapshot)
		return q, nil
	}
	apply := func(ctx context.Context, q generated.HostingLifecycleRequest, actor identity.Principal) (hostinglifecycle.Outcome, error) {
		callbacks++
		ctx = identity.WithVerifiedPrincipal(ctx, actor)
		executing = true
		check := func() error { return repo.Authorize(ctx, q) }
		before, e := provider.ObserveResources(ctx, resourceRequest(check), secret)
		if e != nil {
			return hostinglifecycle.Outcome{}, e
		}
		if hostinglifecycle.Digest(before) != q.ObservedDigest {
			return hostinglifecycle.Outcome{}, failure.New(generated.ErrorCodePlanStale, "provider-preimage", false)
		}
		actual, e := provider.ApplyResources(ctx, resourceRequest(check), secret)
		if e != nil {
			return hostinglifecycle.Outcome{}, e
		}
		return hostinglifecycle.Outcome{Status: "succeeded", ResultDigest: hostinglifecycle.Digest(actual), OwnedResources: []generated.HostingOwnedResource{{Schema: generated.SchemaIDHostingOwnedResource, SchemaVersion: "1.0.0", Kind: "coolify-project", ExternalID: actual.ProjectUUID, ParentID: "team-one"}, {Schema: generated.SchemaIDHostingOwnedResource, SchemaVersion: "1.0.0", Kind: "coolify-environment", ExternalID: fmt.Sprint(actual.EnvironmentID), ParentID: actual.ProjectUUID}}}, nil
	}
	revisions := store.NewPlanRepository(authority)
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), clock)
	if err != nil {
		t.Fatal(err)
	}
	observations, err := planengine.NewStateObservationReader(revisions)
	if err != nil {
		t.Fatal(err)
	}
	plans, err := planengine.NewService(planengine.Config{Repository: revisions, Observations: observations, Clock: clock, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "control-plane", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if err != nil {
		t.Fatal(err)
	}
	evaluator := authorization.NewEvaluator(store.NewEffectiveAuthorizationRepository(authority))
	ackRepo := store.NewAcknowledgementRepository(authority)
	ack, err := acknowledgement.NewService(acknowledgement.Config{Repository: ackRepo, Plans: roleTestPlans{plans}, Authorizer: evaluator, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(authority), Plans: plans, Admission: runengine.NewAdmissionGate(ack, clock), Adapters: adapter.NewRegistry(), Core: runengine.CoreRouter{HostingLifecycle: &runengine.HostingLifecycleEffect{Repository: repo, Approvals: ackRepo, Apply: apply}}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "1.0.0", ReleaseBuildID: "test"}, func() (string, error) { n++; return fmt.Sprintf("grant-request-%d", n), nil })
	app, err := NewApplication(Config{Authority: authority, Authorizer: store.NewReadAuthorizer(authority), Reads: store.NewReadRepository(authority), Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	auth := EffectiveAuthorizationConfig{Authorizer: evaluator, Recorder: store.NewEffectiveAuthorizationRepository(authority), WorkflowOwners: authority, Clock: clock}
	for _, e := range []error{RegisterHostingLifecycleOperations(app, HostingLifecycleOperations{Lifecycles: repo, Declarations: declarations, Results: factory, Prepare: prepare}), RegisterDeclarationPlanOperations(app, DeclarationPlanConfig{Declarations: declarations, Plans: plans, Results: factory, Authorization: auth}), RegisterRunOperations(app, RunOperationConfig{Runs: engine, Plans: revisions, Acknowledgements: ack, Results: factory, Authorization: auth})} {
		if e != nil {
			t.Fatal(e)
		}
	}
	registerLifecycleBrowserApproval(t, app, ack, plans, factory)
	serve := func(method, path string, input any) *httptest.ResponseRecorder {
		now = time.Now().UTC().Truncate(time.Second)
		var body []byte
		if input != nil {
			body, _ = json.Marshal(input)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(body)).WithContext(ctx)
		if input != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		return w
	}
	post := func(path string, input, out any) {
		t.Helper()
		w := serve(http.MethodPost, path, input)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		var envelope struct{ Data json.RawMessage }
		if json.Unmarshal(w.Body.Bytes(), &envelope) != nil || json.Unmarshal(envelope.Data, out) != nil {
			t.Fatal("bad response")
		}
	}
	fixtureDB, e := sql.Open("sqlite3", db)
	if e != nil {
		t.Fatal(e)
	}
	defer fixtureDB.Close()
	seed := admissionSQL{t, fixtureDB}
	if fault == "device-revoked" {
		seed.exec(`INSERT INTO operator_devices VALUES('hosting-device','human-a','approved',1,'now','now')`)
		principal.DeviceID = "hosting-device"
		ctx = identity.WithVerifiedPrincipal(context.Background(), principal)
	}
	revision, e := revisions.CurrentRevision(ctx)
	if e != nil {
		t.Fatal(e)
	}
	draft := generated.HostingLifecycleDraftRequest{Schema: generated.SchemaIDHostingLifecycleDraftRequest, SchemaVersion: "1.0.0", TargetID: policyTarget, Action: "resources.apply", ExpectedStateRevision: revision.StateRevision, RecoveryEpoch: revision.RecoveryEpoch, IdempotencyKey: "hosting-draft", ReasonDigest: digest}
	denied := draft
	denied.TargetID = "foreign"
	if w := serve(http.MethodPost, "/api/v1/hosting/lifecycle-drafts", denied); w.Code != 403 || providerReads != 0 {
		t.Fatal("denied scope contacted provider", w.Code, providerReads, w.Body.String())
	}
	var declaration generated.DeclarationRevision
	post("/api/v1/hosting/lifecycle-drafts", draft, &declaration)
	if writes != 0 || callbacks != 0 || declaration.HostingLifecycle == nil {
		t.Fatal("preparation mutated provider", writes, callbacks)
	}
	prep, e := plans.Prepare(ctx, declaration.DeclarationID, declaration.Revision)
	if e != nil {
		t.Fatal(e)
	}
	var presentation generated.PlanPresentation
	post("/api/v1/declarations/"+declaration.DeclarationID+"/plans", generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: declaration.DeclarationID, DeclarationRevision: declaration.Revision, ExpectedStateRevision: prep.ExpectedStateRevision, RecoveryEpoch: prep.RecoveryEpoch, ObservationFingerprint: prep.ObservationFingerprint, IdempotencyKey: "hosting-plan", Extensions: declaration.Extensions}, &presentation)
	p := presentation.Plan
	if p.HostingLifecycle == nil || p.Risk != "control-plane" || p.AuthorizationBranch != "human" {
		t.Fatal("plan lost hosting authority", p)
	}
	ref := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, RecoveryEpoch: p.Binding.RecoveryEpoch, IdempotencyKey: "hosting-apply", Extensions: []generated.ContractExtension{}}
	if w := serve(http.MethodPost, "/api/v1/plans/"+p.PlanID+"/execute", ref); w.Code < 400 || callbacks != 0 || writes != 0 {
		t.Fatal("unacknowledged provider effect", w.Code)
	}
	var approval generated.ApprovalStatus
	post("/api/v1/plans/"+p.PlanID+"/approval-request", ref, &approval)
	switch fault {
	case "author-revoked":
		seed.exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='hosting-author'`)
	case "epoch-changed":
		seed.exec(`UPDATE system_meta SET recovery_epoch=recovery_epoch+1 WHERE id=1`)
	case "device-revoked":
		seed.exec(`UPDATE operator_devices SET status='revoked',device_revision=2 WHERE device_id='hosting-device'`)
	}
	w := serve(http.MethodPost, "/api/v1/plans/"+p.PlanID+"/execute", ref)
	if fault == "author-revoked" || fault == "epoch-changed" || fault == "device-revoked" {
		if w.Code < 400 || callbacks != 0 || writes != 0 {
			t.Fatal("revoked scope executed", w.Code, callbacks, writes)
		}
		return
	}
	if callbacks != 1 {
		t.Fatal("missing exact execution", callbacks, w.Code, w.Body.String())
	}
	expected := "succeeded"
	if fault != "none" {
		expected = "partial"
	}
	result := serve(http.MethodGet, "/api/v1/hosting/hosting-a/lifecycle", nil)
	if result.Code != 200 || !bytes.Contains(result.Body.Bytes(), []byte(`"status":"`+expected+`"`)) {
		t.Fatal("wrong lifecycle result", result.Code, result.Body.String())
	}
	if fault == "none" && (!project || !environment || writes != 2 || !bytes.Contains(result.Body.Bytes(), []byte(`"externalId":"project-a"`))) {
		t.Fatal("provider state/ownership missing", project, environment, writes)
	}
	priorWrites := writes
	serve(http.MethodPost, "/api/v1/plans/"+p.PlanID+"/execute", ref)
	ref.IdempotencyKey = "hosting-again"
	serve(http.MethodPost, "/api/v1/plans/"+p.PlanID+"/execute", ref)
	if callbacks != 1 || writes != priorWrites {
		t.Fatal("attempt replayed", callbacks, writes)
	}
}
