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
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServiceImportApprovedAPI(t *testing.T) {
	for _, fault := range []string{"none", "observation-changed", "author-revoked", "epoch-changed", "device-revoked"} {
		t.Run(fault, func(t *testing.T) { testServiceImportApprovedAPI(t, fault) })
	}
}
func testServiceImportApprovedAPI(t *testing.T, fault string) {
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	digest := hostaction.Digest("synthetic-grant-setup")
	human := "human-a"
	policyTarget := "service-a"
	db := filepath.Join(dir, "control.db")
	read := generated.LocalSetupReadGrant{Schema: generated.SchemaIDLocalSetupReadGrant, SchemaVersion: "1.0.0", Capability: "service.read", ResourceKind: "service", ResourceID: policyTarget}
	effective := []generated.LocalSetupEffectiveGrant{}
	for _, x := range []struct{ id, action, cap, kind, branch string }{
		{"policy-read", "read", "service.read", "service", "none"},
		{"policy-write", "author", "service.import.prepare", "service", "none"},
		{"policy-ack", "acknowledge", "plan.acknowledge", "plan-target", "human"},
		{"policy-execute", "execute", "service.import", "execution-target", "human"},
	} {
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
	policy := servicecatalog.Policy{Definition: generated.ServiceDefinition{Schema: generated.SchemaIDServiceDefinition, SchemaVersion: "1.0.0", ServiceID: "service-a", EnvironmentID: "development", OwnerID: human, HostID: "host-a", HostIdentityDigest: digest, BindingID: "binding-a", BindingDigest: digest}, ResourceKeyDigest: hostaction.Digest("resource-a")}
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: db, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock, NetworkConnectExcludedHostIDs: []string{"excluded-synthetic"}, ServiceImportPolicies: []servicecatalog.Policy{policy}, InitialSetup: &setup})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	principal := identity.Principal{ID: human, Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	ctx := identity.WithVerifiedPrincipal(context.Background(), principal)
	services := store.NewServiceRepository(authority)
	providerReads := 0
	verifyReads := 0
	changedObservation := false
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
	engine, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(authority), Plans: plans, Admission: runengine.NewAdmissionGate(ack, clock), Adapters: adapter.NewRegistry(), Core: runengine.CoreRouter{ServiceImport: &runengine.ServiceImportEffect{Repository: services, Approvals: ackRepo, VerifyImport: func(ctx context.Context, in generated.ServiceImportRequest, actor identity.Principal) error {
		verifyReads++
		if fault == "device-revoked" {
			if actor.DeviceID != "service-device" {
				return fmt.Errorf("run device attribution lost")
			}
			faultDB, e := sql.Open("sqlite3", db)
			if e != nil {
				return e
			}
			defer faultDB.Close()
			if _, e = faultDB.Exec(`UPDATE operator_devices SET status='revoked',device_revision=2 WHERE device_id='service-device'`); e != nil {
				return e
			}
			var binding store.GrantBatchApply
			if e = faultDB.QueryRow(`SELECT r.run_id,r.plan_id,r.plan_digest,s.step_id,s.active_lease_id FROM plan_runs r JOIN plan_run_steps s ON s.run_id=r.run_id WHERE r.status='running' AND s.adapter_id='core.service-import'`).Scan(&binding.RunID, &binding.PlanID, &binding.PlanDigest, &binding.StepID, &binding.LeaseID); e != nil {
				return e
			}
			binding.Attribution = audit.Attribution{AuthenticatedPrincipalID: actor.ID, AuthenticatedPrincipalMethod: actor.Method, ResponsibleHumanPrincipalID: &human}
			if _, e = services.ExecutionActor(ctx, binding); store.Code(e) != generated.ErrorCodeAuthorizationDenied {
				return fmt.Errorf("revoked execution device actor accepted: %v", e)
			}
		}
		if changedObservation {
			return failure.New(generated.ErrorCodePlanStale, "synthetic-observation", false)
		}
		if in.ObservationDigest != digest {
			return fmt.Errorf("observation not sealed")
		}
		return nil
	}}}, Clock: clock})
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
	for _, err := range []error{RegisterServiceOperations(app, ServicesOperations{Services: services, Declarations: declarations, Results: factory, Prepare: func(ctx context.Context, in generated.ServiceImportDraftRequest) (generated.ServiceImportRequest, error) {
		out, err := services.Prepare(ctx, in)
		if err != nil {
			return out, err
		}
		providerReads++
		out.ObservationDigest = digest
		return out, nil
	}, Observe: func(ctx context.Context, id string) (generated.ServiceObservation, error) {
		record, err := services.Get(ctx, id)
		if err != nil {
			return generated.ServiceObservation{}, err
		}
		providerReads++
		return generated.ServiceObservation{ServiceID: id, BindingDigest: record.Definition.BindingDigest, StateRevision: record.StateRevision, RecoveryEpoch: record.RecoveryEpoch}, nil
	}}), RegisterDeclarationPlanOperations(app, DeclarationPlanConfig{Declarations: declarations, Plans: plans, Results: factory, Authorization: auth}), RegisterRunOperations(app, RunOperationConfig{Runs: engine, Plans: revisions, Acknowledgements: ack, Results: factory, Authorization: auth})} {
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
	fixtureDB, err := sql.Open("sqlite3", db)
	if err != nil {
		t.Fatal(err)
	}
	defer fixtureDB.Close()
	seed := admissionSQL{t, fixtureDB}
	if fault == "device-revoked" {
		seed.exec(`INSERT INTO operator_devices VALUES('service-device','human-a','approved',1,'now','now')`)
		principal.DeviceID = "service-device"
		ctx = identity.WithVerifiedPrincipal(context.Background(), principal)
	}
	input := admissionAccessInput(t)
	seed.host(input, "host-a", digest)
	seed.host(input, "excluded-synthetic", hostaction.Digest("excluded-identity"))
	revision, err := revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	draft := generated.ServiceImportDraftRequest{Schema: generated.SchemaIDServiceImportDraftRequest, SchemaVersion: "1.0.0", ServiceID: "service-a", BindingID: "binding-a", ExpectedStateRevision: revision.StateRevision, RecoveryEpoch: revision.RecoveryEpoch, IdempotencyKey: "service-import", ReasonDigest: digest}
	// A denied target never reaches the synthetic provider observer.
	denied := draft
	denied.ServiceID = "unassigned-service"
	if w := serve(http.MethodPost, "/api/v1/services/import-drafts", denied); w.Code != http.StatusForbidden || providerReads != 0 {
		t.Fatal("denied preparation read provider", w.Code, providerReads, w.Body.String())
	}
	var declaration generated.DeclarationRevision
	post("/api/v1/services/import-drafts", draft, &declaration)
	if providerReads != 1 || declaration.ServiceImport == nil {
		t.Fatal("provider observation not bound", providerReads)
	}
	if w := serve(http.MethodGet, "/api/v1/services/service-a", nil); w.Code == 200 {
		t.Fatal("inert declaration registered service")
	}
	var count int
	if fixtureDB.QueryRow(`SELECT COUNT(*) FROM service_catalog`).Scan(&count) != nil || count != 0 {
		t.Fatal("draft changed catalog", count)
	}
	prep, err := plans.Prepare(ctx, declaration.DeclarationID, declaration.Revision)
	if err != nil {
		t.Fatal(err)
	}
	var presentation generated.PlanPresentation
	post("/api/v1/declarations/"+declaration.DeclarationID+"/plans", generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: declaration.DeclarationID, DeclarationRevision: declaration.Revision, ExpectedStateRevision: prep.ExpectedStateRevision, RecoveryEpoch: prep.RecoveryEpoch, ObservationFingerprint: prep.ObservationFingerprint, IdempotencyKey: "service-plan", Extensions: declaration.Extensions}, &presentation)
	p := presentation.Plan
	if p.ServiceImport == nil || p.ServiceImport.ObservationDigest != digest || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || p.Risk != "control-plane" {
		t.Fatal("service plan lost exact intent", p)
	}
	reference := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, RecoveryEpoch: p.Binding.RecoveryEpoch, IdempotencyKey: "service-apply", Extensions: []generated.ContractExtension{}}
	if w := serve(http.MethodPost, "/api/v1/plans/"+p.PlanID+"/execute", reference); w.Code < 400 || verifyReads != 0 {
		t.Fatal("unacknowledged import reached effect", w.Code, verifyReads)
	}
	var approval generated.ApprovalStatus
	post("/api/v1/plans/"+p.PlanID+"/approval-request", reference, &approval)
	switch fault {
	case "observation-changed":
		changedObservation = true
	case "author-revoked":
		seed.exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='policy-write'`)
	case "epoch-changed":
		seed.exec(`UPDATE system_meta SET recovery_epoch=recovery_epoch+1 WHERE id=1`)
	}
	if fault != "none" {
		w := serve(http.MethodPost, "/api/v1/plans/"+p.PlanID+"/execute", reference)
		if w.Code < 400 {
			t.Fatal("stale import succeeded", fault, w.Body.String())
		}
		if fixtureDB.QueryRow(`SELECT COUNT(*) FROM service_catalog`).Scan(&count) != nil || count != 0 {
			t.Fatal("denied import changed catalog", fault, count)
		}
		return
	}
	var execution generated.RunPresentation
	post("/api/v1/plans/"+p.PlanID+"/execute", reference, &execution)
	if execution.Run.Status != "succeeded" || verifyReads != 1 {
		t.Fatal("approved service import failed", execution, verifyReads)
	}
	if fixtureDB.QueryRow(`SELECT COUNT(*) FROM service_catalog`).Scan(&count) != nil || count != 1 {
		t.Fatal("registration missing", count)
	}
	if fixtureDB.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type='service.import-applied' AND principal_id='human-a' AND target_id='service-a' AND before_fingerprint IS NOT NULL`).Scan(&count) != nil || count != 1 {
		t.Fatal("attributed service audit missing", count)
	}
	if w := serve(http.MethodGet, "/api/v1/services/service-a", nil); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"hostAdmission":"not-verified"`)) {
		t.Fatal("record missing registration truth", w.Code, w.Body.String())
	}
	w := serve(http.MethodGet, "/api/v1/services?limit=1", nil)
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"serviceId":"service-a"`)) {
		t.Fatal("scoped list missing record", w.Code, w.Body.String())
	}
	if w := serve(http.MethodGet, "/api/v1/services?after=service-a&limit=1", nil); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"services":[]`)) {
		t.Fatal("continuation repeated record", w.Code, w.Body.String())
	}
	if w := serve(http.MethodPost, "/api/v1/services/import-drafts", draft); w.Code < 400 {
		t.Fatal("stale request replay accepted")
	}
	current, _ := revisions.CurrentRevision(ctx)
	draft.ExpectedStateRevision = current.StateRevision
	draft.IdempotencyKey = "duplicate-import"
	if w := serve(http.MethodPost, "/api/v1/services/import-drafts", draft); w.Code < 400 {
		t.Fatal("existing service/resource ownership accepted")
	}
	reference.IdempotencyKey = "second-import-run"
	if w := serve(http.MethodPost, "/api/v1/plans/"+p.PlanID+"/execute", reference); w.Code < 400 {
		t.Fatal("consumed acknowledgement reused")
	}
	beforeReads := providerReads
	seed.exec(`INSERT INTO effective_authorization_principals VALUES('service-reader','human','active',1,'now','now')`)
	seed.exec(`INSERT INTO read_principals VALUES('service-reader','active',1,'now','now')`)
	seed.exec(`INSERT INTO effective_authorization_grants VALUES('scoped-reader','service-reader','reader','read','service.read','service','service-a',NULL,1,'active','now','now')`)
	operatorCtx := ctx
	ctx = identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "service-reader", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman})
	if w := serve(http.MethodGet, "/api/v1/services/service-a", nil); w.Code != 200 {
		t.Fatal("exact scoped reader denied before revocation", w.Code, w.Body.String())
	}
	seed.exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='scoped-reader'`)
	for _, path := range []string{"/api/v1/services", "/api/v1/services/service-a", "/api/v1/services/service-a/observation"} {
		if w := serve(http.MethodGet, path, nil); w.Code != http.StatusForbidden || bytes.Contains(w.Body.Bytes(), []byte(`"bindingId":"binding-a"`)) {
			t.Fatal("revoked service scope returned private data", path, w.Code, w.Body.String())
		}
	}
	if providerReads != beforeReads {
		t.Fatal("denied observation contacted provider")
	}
	ctx = operatorCtx
	// Exclusion follows a physical identity through historical alias ownership.
	seed.exec(`INSERT INTO host_alias_history(alias_id,owner_revision,owner_host_id,owner_identity_digest,ownership_generation,event_digest,event_bytes) VALUES('excluded-synthetic',1,'former-name',?,1,?,?)`, digest, hostaction.Digest("excluded-alias"), []byte(`{}`))
	if _, err = services.Get(ctx, "service-a"); store.Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatal("excluded historical identity remained readable", err)
	}
	if fixtureDB.QueryRow(`SELECT COUNT(*) FROM service_catalog`).Scan(&count) != nil || count != 1 {
		t.Fatal("denials lost registration", count)
	}
}
