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
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
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

func TestGrantBatchApprovedAPIFromInitialSetup(t *testing.T) {
	for _, variant := range []string{"fresh-host-workflow", "atomic-read-sync-failure", "subject-revision-changed", "recovery-epoch-changed", "policy-author-revoked", "acknowledgement-replayed"} {
		t.Run(variant, func(t *testing.T) { testGrantBatchApprovedAPI(t, variant) })
	}
}

func testGrantBatchApprovedAPI(t *testing.T, variant string) {
	failReadSync := variant == "atomic-read-sync-failure"
	denyBeforeExecution := variant != "fresh-host-workflow" && variant != "acknowledgement-replayed" && !failReadSync
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	digest := hostaction.Digest("synthetic-grant-setup")
	human := "human-a"
	db := filepath.Join(dir, "control.db")
	read := generated.LocalSetupReadGrant{Schema: generated.SchemaIDLocalSetupReadGrant, SchemaVersion: "1.0.0", Capability: "authorization.policy.read", ResourceKind: "authorization-policy", ResourceID: human}
	effective := []generated.LocalSetupEffectiveGrant{}
	for _, x := range []struct{ id, action, cap, kind, branch string }{{"policy-read", "read", "authorization.policy.read", "authorization-policy", "none"}, {"policy-write", "author", "authorization.policy.write", "authorization-policy", "none"}, {"policy-ack", "acknowledge", "plan.acknowledge", "plan-target", "human"}, {"policy-execute", "execute", "identity.change", "execution-target", "human"}} {
		effective = append(effective, generated.LocalSetupEffectiveGrant{Schema: generated.SchemaIDLocalSetupEffectiveGrant, SchemaVersion: "1.0.0", GrantID: x.id, RoleID: "control-plane-admin", Action: x.action, Capability: x.cap, ResourceKind: x.kind, ResourceID: human, Branch: x.branch})
	}
	request := generated.LocalSetupReviewRequest{Schema: generated.SchemaIDLocalSetupReviewRequest, SchemaVersion: "1.0.0", SetupID: "grant-setup", HostIdentityDigest: digest, InitialHumanID: human, ServiceUID: int64(os.Geteuid()), InitialAdministratorUID: int64(os.Geteuid()), ProfileSHA256: digest, DatabasePath: db, ReleaseManifestPath: "/synthetic/manifest.json", ReleaseManifestDigest: digest, ReleasePolicyPath: "/synthetic/policy.json", ReleasePolicyDigest: digest, ExecutableAssetID: "linux-arm64", ReleaseBuildID: "test", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), RequestNonceDigest: digest, InitialReadGrants: []generated.LocalSetupReadGrant{read}, InitialEffectiveGrants: effective}
	review := store.InitialSetupReview{Request: request, RequestDigest: digest, Acknowledgement: store.InitialAcknowledgementBinding{HumanID: human, AuthorityID: "fixture-authority", Method: identity.CloudflareAccessMethod, ProfileDigest: digest, ExternalScopeID: "scope/synthetic", ExternalSubjectID: "synthetic@example.test", DeliveryTargetID: "delivery/synthetic"}}
	raw, _ := json.Marshal(review)
	setup := store.InitialSetup{SetupID: request.SetupID, HumanID: human, ReviewJSON: raw, ReviewDigest: hostaction.BytesDigest(raw), RequestDigest: digest, ExpiresAt: now.Add(time.Hour), ReadGrants: []store.InitialReadGrant{{Capability: read.Capability, ResourceKind: read.ResourceKind, ResourceID: human}}}
	for _, g := range effective {
		branch := g.Branch
		if branch == "none" {
			branch = ""
		}
		setup.EffectiveGrants = append(setup.EffectiveGrants, store.InitialEffectiveGrant{GrantID: g.GrantID, RoleID: g.RoleID, Action: g.Action, Capability: g.Capability, ResourceKind: g.ResourceKind, ResourceID: g.ResourceID, Branch: branch})
	}
	setup.Approval = store.InitialSetupApproval{HumanID: human, AuthorityID: "fixture-authority", Method: identity.CloudflareAccessMethod, ReviewDigest: setup.ReviewDigest, RequestDigest: digest, DecidedAt: now.Add(-time.Minute)}
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: db, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock, InitialSetup: &setup})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	principal := identity.Principal{ID: human, Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	ctx := identity.WithVerifiedPrincipal(context.Background(), principal)
	grants := store.NewGrantBatchRepository(authority)
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
	engine, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(authority), Plans: plans, Admission: runengine.NewAdmissionGate(ack, clock), Adapters: adapter.NewRegistry(), Core: runengine.CoreRouter{Authorization: &runengine.GrantBatchEffect{Repository: grants, Approvals: ackRepo}}, Clock: clock})
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
	for _, err := range []error{RegisterDeclarationPlanOperations(app, DeclarationPlanConfig{Declarations: declarations, Plans: plans, Results: factory, Authorization: auth}), RegisterAuthorizationGrantOperations(app, AuthorizationGrantOperations{Grants: grants, Declarations: declarations, Results: factory}), RegisterRunOperations(app, RunOperationConfig{Runs: engine, Plans: revisions, Acknowledgements: ack, Results: factory, Authorization: auth})} {
		if err != nil {
			t.Fatal(err)
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
	grantRevision := int64(1)
	declarationRevision := int64(0)
	applyDraft := func(doc generated.DeclarationRevision, key string) {
		t.Helper()
		prep, err := plans.Prepare(ctx, doc.DeclarationID, doc.Revision)
		if err != nil {
			t.Fatal(err)
		}
		var p generated.PlanPresentation
		post("/api/v1/declarations/"+doc.DeclarationID+"/plans", generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: doc.DeclarationID, DeclarationRevision: doc.Revision, ExpectedStateRevision: prep.ExpectedStateRevision, RecoveryEpoch: prep.RecoveryEpoch, ObservationFingerprint: prep.ObservationFingerprint, IdempotencyKey: "plan-" + key, Extensions: doc.Extensions}, &p)
		ref := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.Plan.PlanID, PlanDigest: p.Plan.PlanDigest, RecoveryEpoch: p.Plan.Binding.RecoveryEpoch, IdempotencyKey: "apply-" + key, Extensions: []generated.ContractExtension{}}
		if w := serve(http.MethodPost, "/api/v1/plans/"+p.Plan.PlanID+"/execute", ref); w.Code == 200 {
			t.Fatal("unacknowledged grant batch executed")
		}
		var approval generated.ApprovalStatus
		post("/api/v1/plans/"+p.Plan.PlanID+"/approval-request", ref, &approval)
		if denyBeforeExecution {
			// Adversarial fault injection after genuine approval, never granting authority.
			faultDB, err := sql.Open("sqlite3", "file:"+db+"?mode=rw")
			if err != nil {
				t.Fatal(err)
			}
			defer faultDB.Close()
			var query string
			switch variant {
			case "subject-revision-changed":
				query = `UPDATE effective_authorization_principals SET grant_revision=grant_revision+1 WHERE principal_id='human-a'`
			case "recovery-epoch-changed":
				query = `UPDATE system_meta SET recovery_epoch=recovery_epoch+1 WHERE id=1`
			case "policy-author-revoked":
				query = `UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='policy-write'`
			}
			if _, err = faultDB.Exec(query); err != nil {
				t.Fatal(err)
			}
			w := serve(http.MethodPost, "/api/v1/plans/"+p.Plan.PlanID+"/execute", ref)
			if w.Code < 400 {
				t.Fatal("changed authority accepted", variant, w.Body.String())
			}
			var count int
			if faultDB.QueryRow(`SELECT COUNT(*) FROM effective_authorization_grants WHERE grant_id='read-subject'`).Scan(&count) != nil || count != 0 {
				t.Fatal("denied apply activated a grant", variant, count)
			}
			return
		}
		var run generated.RunPresentation
		if failReadSync {
			w := serve(http.MethodPost, "/api/v1/plans/"+p.Plan.PlanID+"/execute", ref)
			var envelope struct{ Data generated.RunPresentation }
			if w.Code != http.StatusBadGateway || json.Unmarshal(w.Body.Bytes(), &envelope) != nil {
				t.Fatal("storage failure did not return durable failed run", w.Code, w.Body.String())
			}
			run = envelope.Data
			if run.Run.Status == "succeeded" {
				t.Fatal("injected storage failure succeeded")
			}
			return
		}
		post("/api/v1/plans/"+p.Plan.PlanID+"/execute", ref, &run)
		if run.Run.Status != "succeeded" {
			t.Fatalf("grant run failed %+v", run)
		}
		if variant == "acknowledgement-replayed" {
			faultDB, err := sql.Open("sqlite3", "file:"+db+"?mode=ro")
			if err != nil {
				t.Fatal(err)
			}
			defer faultDB.Close()
			var before, after int64
			if faultDB.QueryRow(`SELECT grant_revision FROM effective_authorization_principals WHERE principal_id=?`, human).Scan(&before) != nil {
				t.Fatal("revision unavailable")
			}
			ref.IdempotencyKey = "second-owner-" + key
			w := serve(http.MethodPost, "/api/v1/plans/"+p.Plan.PlanID+"/execute", ref)
			if w.Code < 400 {
				t.Fatal("consumed actual acknowledgement accepted for a second run", w.Body.String())
			}
			if faultDB.QueryRow(`SELECT grant_revision FROM effective_authorization_principals WHERE principal_id=?`, human).Scan(&after) != nil || before != after {
				t.Fatal("replay changed permissions", before, after)
			}
			return
		}
		grantRevision++
		declarationRevision = p.Plan.Binding.DeclarationRevision
		if w := serve(http.MethodGet, "/api/v1/runs/"+run.Run.RunID, nil); w.Code != 200 {
			t.Fatal("run navigation lost after revision rollover", w.Code, w.Body.String())
		}
	}
	for _, changeKind := range []string{"add", "revoke"} {
		rev, err := revisions.CurrentRevision(ctx)
		if err != nil {
			t.Fatal(err)
		}
		batch := generated.AuthorizationGrantBatchRequest{Schema: generated.SchemaIDAuthorizationGrantBatchRequest, SchemaVersion: "1.0.0", PrincipalID: human, ExpectedGrantRevision: grantRevision, ExpectedDeclarationRevision: declarationRevision, ExpectedStateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch, IdempotencyKey: "batch-" + changeKind, ReasonDigest: digest, Changes: []generated.AuthorizationGrantChange{{Schema: generated.SchemaIDAuthorizationGrantChange, SchemaVersion: "1.0.0", GrantID: "read-subject", Change: changeKind, RoleID: "reader", Action: "read", Capability: "host.read", ResourceKind: "host", ResourceID: "subject-a"}}}
		var doc generated.DeclarationRevision
		post("/api/v1/authorization/grant-batches", batch, &doc)
		if failReadSync {
			faultDB, err := sql.Open("sqlite3", "file:"+db+"?mode=rw")
			if err != nil {
				t.Fatal(err)
			}
			defer faultDB.Close()
			// Fail after effective writes but before legacy read synchronization.
			// This is storage fault injection, never grant seeding.
			if _, err = faultDB.Exec(`CREATE TRIGGER grant_test_read_fault BEFORE INSERT ON read_grants WHEN NEW.resource_id='subject-a' BEGIN SELECT RAISE(ABORT,'synthetic read synchronization failure'); END`); err != nil {
				t.Fatal(err)
			}
			applyDraft(doc, changeKind)
			var count, revision, readRevision int64
			if faultDB.QueryRow(`SELECT COUNT(*) FROM effective_authorization_grants WHERE grant_id='read-subject'`).Scan(&count) != nil || count != 0 {
				t.Fatal("partial effective grant survived rollback", count)
			}
			if faultDB.QueryRow(`SELECT grant_revision FROM effective_authorization_principals WHERE principal_id=?`, human).Scan(&revision) != nil || revision != 1 {
				t.Fatal("effective revision changed on failed batch", revision)
			}
			if faultDB.QueryRow(`SELECT grant_revision FROM read_principals WHERE principal_id=?`, human).Scan(&readRevision) != nil || readRevision != 1 {
				t.Fatal("read revision changed on failed batch", readRevision)
			}
			return
		}
		denied := authorization.Request{Action: authorization.ActionRead, Target: authorization.Target{Capability: "host.read", ResourceKind: "host", ResourceID: "subject-a"}}
		before, err := evaluator.Authorize(ctx, principal, denied)
		if err != nil || before.Allowed != (changeKind == "revoke") {
			t.Fatal("draft changed effective grants", before, err)
		}
		applyDraft(doc, changeKind)
		if denyBeforeExecution || variant == "acknowledgement-replayed" {
			return
		}
		after, err := evaluator.Authorize(ctx, principal, denied)
		if err != nil || after.Allowed != (changeKind == "add") {
			t.Fatal("approved changes not effective", after, err)
		}
		_, readErr := store.NewReadAuthorizer(authority).AuthorizeRead(ctx, principal, authorization.ReadTarget{Capability: "host.read", ResourceKind: "host", ResourceID: "subject-a"})
		if (readErr == nil) != (changeKind == "add") {
			t.Fatal("legacy read diverged", readErr)
		}

	}
	rev, err := revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	batch := generated.AuthorizationGrantBatchRequest{Schema: generated.SchemaIDAuthorizationGrantBatchRequest, SchemaVersion: "1.0.0", PrincipalID: human, ExpectedGrantRevision: grantRevision, ExpectedDeclarationRevision: declarationRevision, ExpectedStateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch, IdempotencyKey: "host-grants", ReasonDigest: digest, Changes: []generated.AuthorizationGrantChange{}}
	for i, g := range []struct{ action, cap, kind, branch string }{
		{"author", "host.discovery.target.prepare", "host-discovery-target", ""},
		{"read", "host.discovery.collect", "host-discovery-target", ""},
		{"read", "host.discovery.read", "host-discovery-target", ""},
		{"author", "host.adoption.prepare", "host-discovery-target", ""},
		{"execute", "host.discovery-target.activate", "execution-target", "human"},
		{"execute", "host.adopt", "execution-target", "human"},
		{"acknowledge", "plan.acknowledge", "plan-target", "human"},
		{"read", "host.read", "host", ""},
	} {
		resource := "replacement-host"
		if g.kind == "host-discovery-target" || g.cap == "host.discovery-target.activate" {
			resource = "target-replacement-host"
		}
		batch.Changes = append(batch.Changes, generated.AuthorizationGrantChange{Schema: generated.SchemaIDAuthorizationGrantChange, SchemaVersion: "1.0.0", GrantID: fmt.Sprintf("host-grant-%d", i), Change: "add", RoleID: "control-plane-admin", Action: g.action, Capability: g.cap, ResourceKind: g.kind, ResourceID: resource, Branch: g.branch})
	}
	batch.Changes = append(batch.Changes, generated.AuthorizationGrantChange{Schema: generated.SchemaIDAuthorizationGrantChange, SchemaVersion: "1.0.0", GrantID: "target-ack", Change: "add", RoleID: "control-plane-admin", Action: "acknowledge", Capability: "plan.acknowledge", ResourceKind: "plan-target", ResourceID: "target-replacement-host", Branch: "human"})
	var doc generated.DeclarationRevision
	post("/api/v1/authorization/grant-batches", batch, &doc)
	applyDraft(doc, "host-grants")
	dbRead, err := sql.Open("sqlite3", "file:"+db+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer dbRead.Close()
	// This helper is supplied only read-only evidence access and cannot seed grants.
	transport := func(application *Application, _ *store.Store, _ *sql.DB, _ time.Time) func(string, string, any) *httptest.ResponseRecorder {
		return func(method, path string, input any) *httptest.ResponseRecorder {
			raw, _ := json.Marshal(input)
			r := httptest.NewRequest(method, path, bytes.NewReader(raw)).WithContext(ctx)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			application.ServeHTTP(w, r)
			return w
		}
	}
	gate := func(*store.HostDiscoveryRepository) runengine.GateVerifier { return grantDiscoveryFixtureGate{} }
	f, target := lifecycleAdoptedFixtureWithGrants(t, &now, transport, gate, true, roleAdmissionFixture{authority: authority, db: dbRead})
	if f.input.HostID != "replacement-host" || target.Target.TargetID != "target-replacement-host" {
		t.Fatal("unexpected host fixture")
	}

}

// The external console witness is synthetic here. Actual immutable plans,
// current administrator grants, acknowledgements, leases and database effects
// remain production paths; this fixture provides no native qualification.
type grantDiscoveryFixtureGate struct{}

func (grantDiscoveryFixtureGate) VerifySecretStep(_ context.Context, p generated.Plan, _ generated.PlanOperation) error {
	if p.HostDiscoveryTarget == nil {
		return fmt.Errorf("missing fixture target")
	}
	return hostdiscovery.ValidateConsoleConfirmation(*p.HostDiscoveryTarget)
}
