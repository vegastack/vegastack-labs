//go:build linux

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type lifecycleBrowserTransport func(*Application, *store.Store, *sql.DB, time.Time) func(string, string, any) *httptest.ResponseRecorder
type lifecycleDiscoveryGate func(*store.HostDiscoveryRepository) runengine.GateVerifier

type lifecycleDiscoveryRepository struct {
	*store.HostDiscoveryRepository
	t *testing.T
}

func (r lifecycleDiscoveryRepository) Begin(ctx context.Context, q hostdiscovery.BeginRequest) (hostdiscovery.Attempt, error) {
	v, e := r.HostDiscoveryRepository.Begin(ctx, q)
	return v, e
}
func (r lifecycleDiscoveryRepository) Complete(ctx context.Context, q hostdiscovery.CompleteRequest) (generated.HostObservation, error) {
	v, e := r.HostDiscoveryRepository.Complete(ctx, q)
	return v, e
}

// The collector replaces only SSH observations. Target activation, discovery
// persistence, administrator identity confirmation and adoption are real core effects.
type lifecycleCollector struct {
	at   *time.Time
	uuid string
}

func (c lifecycleCollector) Collect(context.Context, hostdiscovery.Target) (hostdiscovery.Collection, error) {
	facts := hostdiscovery.Facts{}
	for _, x := range [][2]string{{"os.id", "debian"}, {"os.version", "13"}, {"os.point-version", "13.6"}, {"architecture", "amd64"}, {"product-uuid", c.uuid}} {
		op := x[0]
		if op == "os.id" || op == "os.version" {
			op = "os-release"
		}
		if op == "os.point-version" {
			op = "debian-version"
		}
		fact := hostdiscovery.Fact(x[0], x[1], op)
		fact.CapturedAt = c.at.Format(time.RFC3339)
		facts = append(facts, fact)
	}
	collection := hostdiscovery.Collection{Facts: facts, Missing: []string{}}
	return collection, hostdiscovery.ValidateCollection(collection)
}

func lifecycleAdoptedFixture(t *testing.T, at *time.Time, transport lifecycleBrowserTransport, gate lifecycleDiscoveryGate, parent ...roleAdmissionFixture) (roleAdmissionFixture, generated.HostDiscoveryTargetDraftRequest) {
	return lifecycleAdoptedFixtureWithGrants(t, at, transport, gate, false, parent...)
}
func lifecycleAdoptedFixtureWithGrants(t *testing.T, at *time.Time, transport lifecycleBrowserTransport, gate lifecycleDiscoveryGate, productGrants bool, parent ...roleAdmissionFixture) (roleAdmissionFixture, generated.HostDiscoveryTargetDraftRequest) {
	t.Helper()
	clock := func() time.Time { return *at }
	var authority *store.Store
	var db *sql.DB
	var err error
	if len(parent) > 0 {
		authority = parent[0].authority
		db = parent[0].db
	} else {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "control.db")
		authority, err = store.Open(context.Background(), store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "1.0.0", BuildVersion: "build-a", Clock: clock})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = authority.Close() })
		db, err = sql.Open("sqlite3", "file:"+path+"?mode=rw")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })

	}
	seed := admissionSQL{t, db}
	if !productGrants {
		seed.exec(`INSERT OR IGNORE INTO effective_authorization_principals VALUES('human-a','human','active',1,'now','now')`)
	}
	ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "human-a", Kind: identity.PrincipalHuman, Method: identity.LocalOSPeerMethod})
	input := admissionAccessInput(t, "aide", "cryptsetup-bin")
	input.ProfileID = "debian-13-amd64"
	uuid := "23900000-0000-4000-8000-000000000001"
	if len(parent) > 0 {
		input.HostID = "replacement-host"
		uuid = "23900000-0000-4000-8000-000000000002"
		input.RollbackSpecification.HostID = input.HostID
	}
	input.HostIdentityDigest = hostadoption.IdentityDigest("product-uuid", uuid)
	input.RollbackSpecification.HostIdentityDigest = input.HostIdentityDigest
	input.RollbackDigest = hostaction.Digest(input.RollbackSpecification)
	f := roleAdmissionFixture{authority: authority, db: db, seed: seed, ctx: ctx, input: input, proofs: admissionSyntheticProvenance{proofs: map[string]store.HostEvidenceProvenance{}}}
	grant := func(id, action, cap, kind, target string, branch any) {
		if productGrants {
			return
		}
		seed.exec(`INSERT OR IGNORE INTO effective_authorization_grants VALUES(?,'human-a','control-plane-admin',?,?,?,?,?,1,'active','now','now')`, "upstream-"+input.HostID+"-"+id, action, cap, kind, target, branch)
	}
	policy := store.NewEffectiveAuthorizationRepository(authority)
	evaluator := authorization.NewEvaluator(policy)
	n := 0
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "1.0.0", ReleaseBuildID: "build-a"}, func() (string, error) { n++; return fmt.Sprintf("upstream-%s-%d", input.HostID, n), nil })
	app, err := NewApplication(Config{Authority: authority, Authorizer: store.NewReadAuthorizer(authority), Reads: store.NewReadRepository(authority), Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	auth := EffectiveAuthorizationConfig{WorkflowOwners: authority, Authorizer: evaluator, Recorder: policy, Clock: clock}
	app.effective = auth
	serve := transport(app, authority, db, *at)
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), clock)
	if err != nil {
		t.Fatal(err)
	}
	targets := store.NewHostDiscoveryRepository(authority)
	hosts := store.NewHostAdoptionRepository(authority)
	revisions := store.NewPlanRepository(authority)
	observations, err := planengine.NewStateObservationReader(revisions)
	if err != nil {
		t.Fatal(err)
	}
	plans, err := planengine.NewService(planengine.Config{HostDiscoveryTargets: targets, HostAdoptions: hosts, Repository: revisions, Observations: observations, Clock: clock, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "control-plane", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if err != nil {
		t.Fatal(err)
	}
	ack, err := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(authority), Plans: roleTestPlans{plans}, Authorizer: evaluator, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	approvals := store.NewAcknowledgementRepository(authority)
	engine, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(authority), Plans: plans, Admission: runengine.NewAdmissionGate(ack, clock), Adapters: adapter.NewRegistry(), Core: runengine.CoreRouter{DiscoveryTarget: &runengine.HostDiscoveryTargetEffect{Repository: targets, Approvals: approvals, RecoveryPrecheck: gate(targets)}, Adoption: &runengine.HostAdoptionEffect{Repository: hosts, Approvals: approvals}}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []error{RegisterDeclarationPlanOperations(app, DeclarationPlanConfig{Declarations: declarations, Plans: plans, Results: factory, Authorization: auth}), RegisterHostDiscoveryOperations(app, HostDiscoveryOperations{Service: &hostdiscovery.Service{Repository: lifecycleDiscoveryRepository{targets, t}, Collector: lifecycleCollector{at, uuid}}, Targets: targets, Declarations: declarations, Results: factory}), RegisterHostAdoptionOperations(app, HostAdoptionOperations{Hosts: hosts, Declarations: declarations, Results: factory}), RegisterRunOperations(app, RunOperationConfig{Runs: engine, Plans: revisions, Acknowledgements: ack, Results: factory, Authorization: auth})} {
		if e != nil {
			t.Fatal(e)
		}
	}
	registerLifecycleBrowserApproval(t, app, ack, plans, factory)
	post := func(path string, in, out any) {
		t.Helper()
		w := serve(http.MethodPost, path, in)
		if w.Code != 200 {
			t.Fatalf("upstream %s: %d %s", path, w.Code, w.Body.String())
		}
		var envelope struct{ Data json.RawMessage }
		if json.Unmarshal(w.Body.Bytes(), &envelope) != nil || json.Unmarshal(envelope.Data, out) != nil {
			t.Fatalf("upstream response %s", w.Body.String())
		}
	}
	execute := func(id string) {
		t.Helper()
		doc, e := declarations.Get(ctx, id, 1)
		if e != nil {
			t.Fatal(e)
		}
		rev, e := revisions.CurrentRevision(ctx)
		if e != nil {
			t.Fatal(e)
		}
		fp, e := observations.CurrentFingerprint(ctx, id, doc.Operations)
		if e != nil {
			t.Fatal(e)
		}
		var presentation struct {
			Plan generated.Plan `json:"plan"`
		}
		post("/api/v1/declarations/"+id+"/plans", generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: id, DeclarationRevision: 1, ExpectedStateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch, ObservationFingerprint: fp, IdempotencyKey: "plan-" + id, Extensions: doc.Extensions}, &presentation)
		p := presentation.Plan
		if p.PlanID == "" {
			t.Fatal("missing upstream plan")
		}
		for i, target := range authorization.ExecutionResourceIDs(p, p.Operations[0]) {
			grant(fmt.Sprintf("execute-%s-%d", id, i), "execute", p.Operations[0].OperationType, "execution-target", target, "human")
			grant(fmt.Sprintf("ack-%s-%d", id, i), "acknowledge", "plan.acknowledge", "plan-target", target, "human")
		}
		// The real Slack decoder timestamps its decision from the wall clock.
		*at = time.Now().UTC().Truncate(time.Second)
		var approval generated.ApprovalStatus
		post("/api/v1/plans/"+p.PlanID+"/approval-request", generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, RecoveryEpoch: p.Binding.RecoveryEpoch, IdempotencyKey: "approve-" + id, Extensions: []generated.ContractExtension{}}, &approval)
		var presentationRun generated.RunPresentation
		post("/api/v1/plans/"+p.PlanID+"/execute", generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, RecoveryEpoch: p.Binding.RecoveryEpoch, IdempotencyKey: "run-" + id, Extensions: []generated.ContractExtension{}}, &presentationRun)
		assertLifecycleDurableRun(t, db, p, presentationRun.Run)
		if presentationRun.Run.Status != "succeeded" {
			t.Fatalf("upstream run: %+v", presentationRun)
		}
	}
	rev, err := revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	draft := admissionTargetDraft(input, input.HostID)
	draft.ExpectedStateRevision = rev.StateRevision
	mode := "preloaded-discovery"
	fingerprint := hostaction.Digest("synthetic-public-key-" + input.HostID)
	draft.Target.CredentialMode = &mode
	draft.Target.CredentialPublicKeyDigest = &fingerprint
	draft.ConsoleConfirmation = &generated.HostDiscoveryConsoleConfirmation{Schema: generated.SchemaIDHostDiscoveryConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: hostaction.Digest(draft.Target)}
	grant("target", "author", "host.discovery.target.prepare", "host-discovery-target", draft.Target.TargetID, nil)
	var submitted generated.HostDiscoveryTargetDraftSubmission
	post("/api/v1/host-discovery-targets/draft", draft, &submitted)
	execute(submitted.DeclarationID)
	grant("collect", "read", "host.discovery.collect", "host-discovery-target", draft.Target.TargetID, nil)
	grant("discovery-read", "read", "host.discovery.read", "host-discovery-target", draft.Target.TargetID, nil)
	rev, err = revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request := generated.HostDiscoveryRequest{Schema: generated.SchemaIDHostDiscoveryRequest, SchemaVersion: "1.0.0", TargetID: draft.Target.TargetID, TargetRevision: 1, ExpectedStateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch, IdempotencyKey: "discover-upstream-" + input.HostID}
	var observed generated.HostDiscoverySubmission
	if raw, err := json.Marshal(request); err != nil || generated.ValidateContractJSON(generated.SchemaIDHostDiscoveryRequest, raw, generated.ContractExact) != nil {
		t.Fatalf("invalid discovery request %s %v", raw, err)
	}
	post("/api/v1/host-observations", request, &observed)
	if observed.OriginalRequestDigest != hostaction.Digest(request) {
		t.Fatal("discovery response lost request binding")
	}
	rev, err = revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	adoption := generated.HostAdoptionRequest{Schema: generated.SchemaIDHostAdoptionRequest, SchemaVersion: "1.0.0", HostID: input.HostID, ObservationID: observed.Observation.ObservationID, ObservationDigest: observed.Observation.ContentDigest, ExpectedStateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch, IdempotencyKey: "adopt-upstream-" + input.HostID, Confirmation: generated.HostIdentityConfirmation{Schema: generated.SchemaIDHostIdentityConfirmation, SchemaVersion: "1.0.0", TargetDigest: observed.Observation.TargetDigest, TargetRevision: 1, IdentityDigest: input.HostIdentityDigest, IdentityClass: "qualified-virtual", IdentityKind: "product-uuid", ConfirmedAt: at.Format(time.RFC3339)}}
	grant("adopt", "author", "host.adoption.prepare", "host-discovery-target", draft.Target.TargetID, nil)
	var adopted generated.HostAdoptionSubmission
	post("/api/v1/host-adoptions/draft", adoption, &adopted)
	execute(adopted.DeclarationID)
	grant("read-host", "read", "host.read", "host", input.HostID, nil)
	host, err := hosts.Get(ctx, input.HostID)
	if err != nil || host.Status != "adopted-unadmitted" {
		t.Fatalf("actual adoption: %+v %v", host, err)
	}
	w := serve(http.MethodGet, "/api/v1/hosts/"+input.HostID, nil)
	if w.Code != 200 {
		t.Fatalf("browser host inspection: %d %s", w.Code, w.Body.String())
	}
	return f, draft
}

func assertLifecycleDurableRun(t *testing.T, db *sql.DB, p generated.Plan, run generated.BrowserRun) {
	t.Helper()
	if run.PlanID != p.PlanID || run.PlanDigest != p.PlanDigest || run.Status != "succeeded" {
		t.Fatalf("browser run does not match exact plan: %+v", run)
	}
	var receipts int
	err := db.QueryRow(`SELECT count(*) FROM execution_receipts e JOIN plan_run_steps s ON s.step_id=e.step_id AND s.run_id=e.run_id JOIN plan_runs r ON r.run_id=s.run_id WHERE r.run_id=? AND r.plan_id=? AND r.plan_digest=? AND r.status='succeeded' AND s.status='succeeded' AND s.effect_state='verified' AND e.status='succeeded'`, run.RunID, p.PlanID, p.PlanDigest).Scan(&receipts)
	if err != nil || receipts != len(p.Operations) {
		t.Fatalf("durable verified receipts=%d operations=%d error=%v", receipts, len(p.Operations), err)
	}
}
