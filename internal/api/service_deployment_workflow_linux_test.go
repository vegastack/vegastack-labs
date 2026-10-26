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

// TestServiceDeploymentApprovedAPI exercises the real API, SQLite, planning,
// acknowledgement and run engine. Only provider/runtime effects are synthetic;
// success here grants no live provider, host or deployment authority.
func TestServiceDeploymentApprovedAPI(t *testing.T) {
	for _, fault := range []string{"none", "unknown-effect", "wrong-owner", "author-revoked", "epoch-changed", "device-revoked"} {
		t.Run(fault, func(t *testing.T) { testServiceDeploymentApprovedAPI(t, fault) })
	}
}
func testServiceDeploymentApprovedAPI(t *testing.T, fault string) {
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
		{"deployment-author", "author", "service.deploy.prepare", "service", "none"},
		{"deployment-execute", "execute", "service.deploy", "execution-target", "human"},
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
	deploymentPolicy := servicecatalog.DeploymentPolicy{Binding: generated.ServiceDeploymentBinding{Schema: generated.SchemaIDServiceDeploymentBinding, SchemaVersion: "1.0.0", ServiceID: "service-a", BindingID: "binding-a", DataPolicy: "stateless", ConfigurationDigest: digest}, Artifacts: []generated.ServiceDeploymentArtifact{{Schema: generated.SchemaIDServiceDeploymentArtifact, SchemaVersion: "1.0.0", ArtifactID: "artifact-a", Repository: "registry.example/app", Digest: digest, ManifestSHA: digest, BundleSHA: digest, PolicySHA: digest}}}
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: db, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock, NetworkConnectExcludedHostIDs: []string{"excluded-synthetic"}, ServiceImportPolicies: []servicecatalog.Policy{policy}, ServiceDeploymentPolicies: []servicecatalog.DeploymentPolicy{deploymentPolicy}, InitialSetup: &setup})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	principal := identity.Principal{ID: human, Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	ctx := identity.WithVerifiedPrincipal(context.Background(), principal)
	services := store.NewServiceRepository(authority)
	providerReads := 0
	verifyReads := 0
	deployCalls := 0
	deployments := store.NewDeploymentRepository(authority)
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
		if in.ObservationDigest != digest {
			return fmt.Errorf("observation not sealed")
		}
		return nil
	}}, ServiceDeployment: &runengine.ServiceDeploymentEffect{Repository: deployments, Approvals: ackRepo, Deploy: func(ctx context.Context, in generated.ServiceDeploymentRequest, actor identity.Principal) (servicecatalog.DeploymentOutcome, error) {
		deployCalls++
		if in.ArtifactProofDigest != servicecatalog.Digest(in.Artifact) || actor.ID != human {
			return servicecatalog.DeploymentOutcome{}, fmt.Errorf("unbound execution")
		}
		if fault == "unknown-effect" {
			return servicecatalog.DeploymentOutcome{ProviderStage: "deploy_attempted", ProviderReceiptID: "receipt-a"}, failure.New(generated.ErrorCodeDependencyUnavailable, "synthetic-provider", false)
		}
		return servicecatalog.DeploymentOutcome{Status: "succeeded", ProviderStage: "queued", ProviderReceiptID: "receipt-a", ReceiptDigest: digest, RuntimeDigest: digest, RunningDigest: in.Artifact.Digest, Running: true, Healthy: true}, nil
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
	for _, err := range []error{RegisterServiceDeploymentOperations(app, ServiceDeploymentOperations{Deployments: deployments, Declarations: declarations, Results: factory, Prepare: func(ctx context.Context, in generated.ServiceDeploymentDraftRequest) (generated.ServiceDeploymentRequest, error) {
		out, e := deployments.Prepare(ctx, in)
		if e != nil {
			return out, e
		}
		out.ArtifactProofDigest = servicecatalog.Digest(out.Artifact)
		if fault == "wrong-owner" {
			out.Definition.OwnerID = "different-owner"
		}
		return out, nil
	}}), RegisterServiceOperations(app, ServicesOperations{Services: services, Declarations: declarations, Results: factory, Prepare: func(ctx context.Context, in generated.ServiceImportDraftRequest) (generated.ServiceImportRequest, error) {
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

	// Complete a real approved import first; registration is prerequisite state.
	var imported generated.RunPresentation
	post("/api/v1/plans/"+p.PlanID+"/execute", reference, &imported)
	if imported.Run.Status != "succeeded" || verifyReads != 1 {
		t.Fatal("fixture registration failed", imported, verifyReads)
	}
	if w := serve(http.MethodGet, "/api/v1/services/service-a/deployment", nil); w.Code != http.StatusNotFound {
		t.Fatal("missing deployment should be 404", w.Code, w.Body.String())
	}
	current, e := revisions.CurrentRevision(ctx)
	if e != nil {
		t.Fatal(e)
	}
	deploymentDraft := generated.ServiceDeploymentDraftRequest{Schema: generated.SchemaIDServiceDeploymentDraftRequest, SchemaVersion: "1.0.0", ServiceID: "service-a", ArtifactID: "artifact-a", Action: "deploy", ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: "deployment-draft", ReasonDigest: digest}
	if fault == "wrong-owner" {
		w := serve(http.MethodPost, "/api/v1/services/deployment-drafts", deploymentDraft)
		if w.Code < 400 || deployCalls != 0 {
			t.Fatal("changed owner accepted", w.Code, w.Body.String())
		}
		return
	}
	var deployedDeclaration generated.DeclarationRevision
	post("/api/v1/services/deployment-drafts", deploymentDraft, &deployedDeclaration)
	if deployedDeclaration.ServiceDeployment == nil || deployCalls != 0 {
		t.Fatal("deployment draft not inert")
	}
	if fixtureDB.QueryRow(`SELECT COUNT(*) FROM service_deployment_attempts`).Scan(&count) != nil || count != 0 {
		t.Fatal("draft created attempt", count)
	}
	if w := serve(http.MethodGet, "/api/v1/services/service-a/deployment", nil); w.Code != http.StatusNotFound {
		t.Fatal("inert draft created result", w.Code, w.Body.String())
	}
	prep, e = plans.Prepare(ctx, deployedDeclaration.DeclarationID, deployedDeclaration.Revision)
	if e != nil {
		t.Fatal(e)
	}
	var deploymentPlan generated.PlanPresentation
	post("/api/v1/declarations/"+deployedDeclaration.DeclarationID+"/plans", generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: deployedDeclaration.DeclarationID, DeclarationRevision: deployedDeclaration.Revision, ExpectedStateRevision: prep.ExpectedStateRevision, RecoveryEpoch: prep.RecoveryEpoch, ObservationFingerprint: prep.ObservationFingerprint, IdempotencyKey: "deployment-plan", Extensions: deployedDeclaration.Extensions}, &deploymentPlan)
	dp := deploymentPlan.Plan
	if dp.ServiceDeployment == nil || dp.ServiceDeployment.Artifact.Digest != digest || dp.Risk != "production-like" || dp.AuthorizationBranch != "human" || dp.ExecutorMode != "central" {
		t.Fatal("deployment plan lost exact boundary", dp)
	}
	ref := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: dp.PlanID, PlanDigest: dp.PlanDigest, RecoveryEpoch: dp.Binding.RecoveryEpoch, IdempotencyKey: "deployment-apply", Extensions: []generated.ContractExtension{}}
	if w := serve(http.MethodPost, "/api/v1/plans/"+dp.PlanID+"/execute", ref); w.Code < 400 || deployCalls != 0 {
		t.Fatal("unacknowledged deployment reached callback", w.Code, deployCalls)
	}
	post("/api/v1/plans/"+dp.PlanID+"/approval-request", ref, &approval)
	switch fault {
	case "author-revoked":
		seed.exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='deployment-author'`)
	case "epoch-changed":
		seed.exec(`UPDATE system_meta SET recovery_epoch=recovery_epoch+1 WHERE id=1`)
	case "device-revoked":
		seed.exec(`UPDATE operator_devices SET status='revoked',device_revision=2 WHERE device_id='service-device'`)
	}
	if fault == "author-revoked" || fault == "epoch-changed" || fault == "device-revoked" {
		w := serve(http.MethodPost, "/api/v1/plans/"+dp.PlanID+"/execute", ref)
		if w.Code < 400 || deployCalls != 0 {
			t.Fatal("revoked deployment reached callback", fault, w.Code, deployCalls, w.Body.String())
		}
		return
	}
	w := serve(http.MethodPost, "/api/v1/plans/"+dp.PlanID+"/execute", ref)
	if fault == "none" && w.Code != http.StatusOK {
		t.Fatal("approved execution failed", w.Code, w.Body.String())
	}
	if deployCalls != 1 {
		t.Fatal("expected one effect callback", deployCalls, w.Body.String())
	}
	result := serve(http.MethodGet, "/api/v1/services/service-a/deployment", nil)
	expected := "succeeded"
	if fault == "unknown-effect" {
		expected = "partial"
	}
	if result.Code != http.StatusOK || !bytes.Contains(result.Body.Bytes(), []byte(`"status":"`+expected+`"`)) || !bytes.Contains(result.Body.Bytes(), []byte(`"providerReceiptId":"receipt-a"`)) {
		t.Fatal("deployment result missing", result.Code, result.Body.String())
	}
	// Exact duplicate and fresh idempotency key both cannot repeat an attempted effect.
	serve(http.MethodPost, "/api/v1/plans/"+dp.PlanID+"/execute", ref)
	ref.IdempotencyKey = "deployment-apply-again"
	serve(http.MethodPost, "/api/v1/plans/"+dp.PlanID+"/execute", ref)
	if deployCalls != 1 {
		t.Fatal("deployment replayed", deployCalls)
	}
	if fixtureDB.QueryRow(`SELECT COUNT(*) FROM service_deployment_attempts`).Scan(&count) != nil || count != 1 {
		t.Fatal("durable attempt count", count)
	}
	if fixtureDB.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type='service.deployment-attempted' AND principal_id='human-a' AND target_id='service-a'`).Scan(&count) != nil || count != 1 {
		t.Fatal("attributed attempt missing", count)
	}
}
