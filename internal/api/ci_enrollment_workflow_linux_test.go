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
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCIEnrollmentApprovedAPI(t *testing.T) {
	for _, fault := range []string{"none", "state-changed", "author-revoked", "execute-revoked", "ack-grant-revoked", "cancelled-at-effect", "lease-revoked-at-effect", "epoch-changed", "device-revoked"} {
		t.Run(fault, func(t *testing.T) { testCIEnrollmentApprovedAPI(t, fault) })
	}
}
func testCIEnrollmentApprovedAPI(t *testing.T, fault string) {
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	digest := hostaction.Digest("synthetic-grant-setup")
	human := "human-a"
	policyTarget := "enrollment-a"
	db := filepath.Join(dir, "control.db")
	read := generated.LocalSetupReadGrant{Schema: generated.SchemaIDLocalSetupReadGrant, SchemaVersion: "1.0.0", Capability: "ci.enrollment.read", ResourceKind: "ci-enrollment", ResourceID: policyTarget}
	effective := []generated.LocalSetupEffectiveGrant{}
	for _, x := range []struct{ id, action, cap, kind, branch string }{
		{"policy-read", "read", "ci.enrollment.read", "ci-enrollment", "none"},
		{"policy-write", "author", "ci.enrollment.prepare", "ci-enrollment", "none"},
		{"policy-ack", "acknowledge", "plan.acknowledge", "plan-target", "human"},
		{"policy-execute", "execute", "ci.enrollment.register", "execution-target", "human"},
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
	binding := generated.CiEnrollmentBinding{Schema: generated.SchemaIDCiEnrollmentBinding, SchemaVersion: "1.0.0", EnrollmentID: policyTarget, OwnerID: human, BindingID: "binding-a", AdapterID: "scm.github", RepositoryID: "101", RepositoryOwnerID: "202", Repository: "private-owner/private-repo", WorkflowID: "303", WorkflowPath: ".github/workflows/private.yml", WorkflowDigest: digest, Revision: strings.Repeat("a", 40), Ref: "refs/heads/main", Event: "push", JobName: "private-job", RunnerGroupID: "404", Labels: []string{"isolated"}}
	frozen, e := serverconfig.FreezeCIEnrollmentBindings([]generated.CiEnrollmentBinding{binding})
	if e != nil {
		t.Fatal(e)
	}
	binding = frozen[0]
	policy := store.CIEnrollmentPolicy{Definition: generated.CiEnrollmentDefinition{Schema: generated.SchemaIDCiEnrollmentDefinition, SchemaVersion: "1.0.0", EnrollmentID: policyTarget, OwnerID: human, BindingID: binding.BindingID, BindingDigest: hostaction.Digest(binding)}, Binding: binding, ResourceKeyDigest: store.CIEnrollmentPolicyKey(binding)}
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: db, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock, NetworkConnectExcludedHostIDs: []string{"excluded-synthetic"}, CIEnrollmentPolicies: []store.CIEnrollmentPolicy{policy}, InitialSetup: &setup})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	principal := identity.Principal{ID: human, Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	ctx := identity.WithVerifiedPrincipal(context.Background(), principal)
	services := store.NewCIEnrollmentRepository(authority)

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
	engine, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(authority), Plans: plans, Admission: runengine.NewAdmissionGate(ack, clock), Adapters: adapter.NewRegistry(), Core: runengine.CoreRouter{CIEnrollment: ciEnrollmentBeforeEffect{next: &runengine.CIEnrollmentEffect{Repository: services, Approvals: ackRepo}, before: func(b runengine.ExactStepBinding) error {
		if fault != "cancelled-at-effect" && fault != "lease-revoked-at-effect" {
			return nil
		}
		faultDB, e := sql.Open("sqlite3", db)
		if e != nil {
			return e
		}
		defer faultDB.Close()
		if fault == "cancelled-at-effect" {
			_, e = faultDB.Exec(`UPDATE plan_runs SET cancellation_requested=1 WHERE run_id=?`, b.Run.RunID)
		} else {
			_, e = faultDB.Exec(`UPDATE target_execution_leases SET status='revoked' WHERE lease_id=?`, b.Lease.LeaseID)
		}
		return e
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
	for _, err := range []error{RegisterCIEnrollmentOperations(app, CIEnrollmentOperations{Enrollments: services, Declarations: declarations, Results: factory, Prepare: services.Prepare}), RegisterDeclarationPlanOperations(app, DeclarationPlanConfig{Declarations: declarations, Plans: plans, Results: factory, Authorization: auth}), RegisterRunOperations(app, RunOperationConfig{Runs: engine, Plans: revisions, Acknowledgements: ack, Results: factory, Authorization: auth})} {
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
	revision, err := revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	draft := generated.CiEnrollmentDraftRequest{Schema: generated.SchemaIDCiEnrollmentDraftRequest, SchemaVersion: "1.0.0", EnrollmentID: "enrollment-a", BindingID: "binding-a", ExpectedStateRevision: revision.StateRevision, RecoveryEpoch: revision.RecoveryEpoch, IdempotencyKey: "service-import", ReasonDigest: digest}
	// A denied target never reaches the synthetic provider observer.
	denied := draft
	denied.EnrollmentID = "unassigned-service"
	if w := serve(http.MethodPost, "/api/v1/ci/enrollments/drafts", denied); w.Code != http.StatusForbidden {
		t.Fatal("denied preparation read provider", w.Code, w.Body.String())
	}
	var declaration generated.DeclarationRevision
	post("/api/v1/ci/enrollments/drafts", draft, &declaration)
	if declaration.CIEnrollment == nil {
		t.Fatal("exact intent missing")
	}
	if w := serve(http.MethodGet, "/api/v1/ci/enrollments/enrollment-a", nil); w.Code == 200 {
		t.Fatal("inert declaration registered service")
	}
	var count int
	if fixtureDB.QueryRow(`SELECT COUNT(*) FROM ci_enrollments`).Scan(&count) != nil || count != 0 {
		t.Fatal("draft changed catalog", count)
	}
	prep, err := plans.Prepare(ctx, declaration.DeclarationID, declaration.Revision)
	if err != nil {
		t.Fatal(err)
	}
	var presentation generated.PlanPresentation
	post("/api/v1/declarations/"+declaration.DeclarationID+"/plans", generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: declaration.DeclarationID, DeclarationRevision: declaration.Revision, ExpectedStateRevision: prep.ExpectedStateRevision, RecoveryEpoch: prep.RecoveryEpoch, ObservationFingerprint: prep.ObservationFingerprint, IdempotencyKey: "service-plan", Extensions: declaration.Extensions}, &presentation)
	p := presentation.Plan
	if p.CIEnrollment == nil || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || p.Risk != "control-plane" {
		t.Fatal("service plan lost exact intent", p)
	}
	reference := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, RecoveryEpoch: p.Binding.RecoveryEpoch, IdempotencyKey: "enrollment-apply", Extensions: []generated.ContractExtension{}}
	if w := serve(http.MethodPost, "/api/v1/plans/"+p.PlanID+"/execute", reference); w.Code < 400 {
		t.Fatal("unacknowledged import reached effect", w.Code)
	}
	var approval generated.ApprovalStatus
	post("/api/v1/plans/"+p.PlanID+"/approval-request", reference, &approval)
	switch fault {
	case "state-changed":
		seed.exec(`UPDATE system_meta SET state_revision=state_revision+1 WHERE id=1`)
	case "execute-revoked":
		seed.exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='policy-execute'`)
	case "ack-grant-revoked":
		seed.exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='policy-ack'`)
	case "author-revoked":
		seed.exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='policy-write'`)
	case "device-revoked":
		seed.exec(`UPDATE operator_devices SET status='revoked',device_revision=2 WHERE device_id='service-device'`)
	case "epoch-changed":
		seed.exec(`UPDATE system_meta SET recovery_epoch=recovery_epoch+1 WHERE id=1`)
	}
	if fault != "none" {
		w := serve(http.MethodPost, "/api/v1/plans/"+p.PlanID+"/execute", reference)
		if w.Code < 400 {
			t.Fatal("stale import succeeded", fault, w.Body.String())
		}
		if fixtureDB.QueryRow(`SELECT COUNT(*) FROM ci_enrollments`).Scan(&count) != nil || count != 0 {
			t.Fatal("denied import changed catalog", fault, count)
		}
		return
	}
	var execution generated.RunPresentation
	post("/api/v1/plans/"+p.PlanID+"/execute", reference, &execution)
	if execution.Run.Status != "succeeded" {
		t.Fatal("approved service import failed", execution)
	}
	if fixtureDB.QueryRow(`SELECT COUNT(*) FROM ci_enrollments`).Scan(&count) != nil || count != 1 {
		t.Fatal("registration missing", count)
	}
	if fixtureDB.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type='ci.enrollment.register-applied' AND principal_id='human-a' AND target_id='enrollment-a' AND before_fingerprint IS NOT NULL`).Scan(&count) != nil || count != 1 {
		t.Fatal("attributed service audit missing", count)
	}
	if w := serve(http.MethodGet, "/api/v1/ci/enrollments/enrollment-a", nil); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"admissionStatus":"not-qualified"`)) {
		t.Fatal("record missing registration truth", w.Code, w.Body.String())
	}
	w := serve(http.MethodGet, "/api/v1/ci/enrollments?limit=1", nil)
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"enrollmentId":"enrollment-a"`)) {
		t.Fatal("scoped list missing record", w.Code, w.Body.String())
	}
	if w := serve(http.MethodGet, "/api/v1/ci/enrollments?after=enrollment-a&limit=1", nil); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"enrollments":[]`)) {
		t.Fatal("continuation repeated record", w.Code, w.Body.String())
	}
	if w := serve(http.MethodPost, "/api/v1/ci/enrollments/drafts", draft); w.Code < 400 {
		t.Fatal("stale request replay accepted")
	}
	current, _ := revisions.CurrentRevision(ctx)
	draft.ExpectedStateRevision = current.StateRevision
	draft.IdempotencyKey = "duplicate-import"
	if w := serve(http.MethodPost, "/api/v1/ci/enrollments/drafts", draft); w.Code < 400 {
		t.Fatal("existing service/resource ownership accepted")
	}
	reference.IdempotencyKey = "second-import-run"
	if w := serve(http.MethodPost, "/api/v1/plans/"+p.PlanID+"/execute", reference); w.Code < 400 {
		t.Fatal("consumed acknowledgement reused")
	}
	seed.exec(`INSERT INTO effective_authorization_principals VALUES('service-reader','human','active',1,'now','now')`)
	seed.exec(`INSERT INTO read_principals VALUES('service-reader','active',1,'now','now')`)
	seed.exec(`INSERT INTO effective_authorization_grants VALUES('scoped-reader','service-reader','reader','read','ci.enrollment.read','ci-enrollment','enrollment-a',NULL,1,'active','now','now')`)
	operatorCtx := ctx
	ctx = identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "service-reader", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman})
	if w := serve(http.MethodGet, "/api/v1/ci/enrollments/enrollment-a", nil); w.Code != 200 {
		t.Fatal("exact scoped reader denied before revocation", w.Code, w.Body.String())
	}
	seed.exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='scoped-reader'`)
	for _, path := range []string{"/api/v1/ci/enrollments", "/api/v1/ci/enrollments/enrollment-a"} {
		if w := serve(http.MethodGet, path, nil); w.Code != http.StatusForbidden || bytes.Contains(w.Body.Bytes(), []byte(`"bindingId":"binding-a"`)) {
			t.Fatal("revoked service scope returned private data", path, w.Code, w.Body.String())
		}
	}
	ctx = operatorCtx
	// The applied policy snapshot survives restart and remains private.
	var private []byte
	if err := fixtureDB.QueryRow(`SELECT binding_bytes FROM ci_enrollments WHERE enrollment_id=?`, policyTarget).Scan(&private); err != nil || !bytes.Contains(private, []byte("private-owner/private-repo")) {
		t.Fatal("private snapshot missing", err)
	}
	for _, path := range []string{"/api/v1/ci/enrollments", "/api/v1/ci/enrollments/enrollment-a"} {
		w := serve(http.MethodGet, path, nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		for _, canary := range []string{"private-owner/private-repo", ".github/workflows/private.yml", "private-job"} {
			if bytes.Contains(w.Body.Bytes(), []byte(canary)) {
				t.Fatal("private binding leaked")
			}
		}
	}
	if _, err := fixtureDB.Exec(`UPDATE ci_enrollments SET digest=?`, digest); err == nil {
		t.Fatal("enrollment mutable")
	}
	if _, err := fixtureDB.Exec(`DELETE FROM ci_enrollments`); err == nil {
		t.Fatal("enrollment deletable")
	}
	fixtureDB.Close()
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(context.Background(), store.Config{DatabasePath: db, Mode: store.OpenExisting, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock, CIEnrollmentPolicies: []store.CIEnrollmentPolicy{policy}})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got, err := store.NewCIEnrollmentRepository(reopened).Get(ctx, policyTarget); err != nil || got.Definition.BindingDigest != policy.Definition.BindingDigest {
		t.Fatal("restart lost enrollment", got, err)
	}
	reopened.Close()
	policy.Binding.JobName = "changed-private-job"
	policy.Definition.BindingDigest = hostaction.Digest(policy.Binding)
	policy.ResourceKeyDigest = store.CIEnrollmentPolicyKey(policy.Binding)
	drifted, err := store.Open(context.Background(), store.Config{DatabasePath: db, Mode: store.OpenExisting, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock, CIEnrollmentPolicies: []store.CIEnrollmentPolicy{policy}})
	if err != nil {
		t.Fatal(err)
	}
	defer drifted.Close()
	if got, err := store.NewCIEnrollmentRepository(drifted).Get(ctx, policyTarget); store.Code(err) != generated.ErrorCodePlanStale || got.Definition.EnrollmentID != "" {
		t.Fatal("profile drift remained usable", got, err)
	}
}

// Inject a state change at the engine/effect boundary, after reservation and acknowledgement.
type ciEnrollmentBeforeEffect struct {
	next   runengine.CoreEffect
	before func(runengine.ExactStepBinding) error
}

func (e ciEnrollmentBeforeEffect) Execute(ctx context.Context, b runengine.ExactStepBinding) (adapter.Effect, error) {
	if err := e.before(b); err != nil {
		return adapter.Effect{}, err
	}
	return e.next.Execute(ctx, b)
}
func (e ciEnrollmentBeforeEffect) Verify(ctx context.Context, b runengine.ExactStepBinding, r adapter.Effect) (adapter.Verification, error) {
	return e.next.Verify(ctx, b, r)
}
