//go:build linux

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/githubci"
	transport "github.com/vegastack/vegastack-labs/internal/adapter/hostaction"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/ci"
	"github.com/vegastack/vegastack-labs/internal/cijobrunner"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
	"golang.org/x/crypto/ssh"
)

// Synthetic gate provenance isolates the controller/store boundary. It resolves
// a real persisted snapshot but does NOT qualify a host; production instead
// requires ciJobReadiness/common gate evaluation. The SSH peer is a typed
// protocol peer, never a fake stock-runner executor. Native #312 owns execution.
type ciJobSnapshotFixture struct{ g *store.GateRepository }

func (f ciJobSnapshotFixture) CheckCIJobHost(ctx context.Context, id string) (store.HostAdmissionSnapshot, error) {
	return f.g.ResolveHostAdmission(ctx, id)
}

type ciJobGateDiagnostic struct {
	t    *testing.T
	gate hostActionGate
}

func (g ciJobGateDiagnostic) VerifySecretStep(ctx context.Context, p generated.Plan, op generated.PlanOperation) error {
	err := g.gate.VerifySecretStep(ctx, p, op)
	if err != nil {
		g.t.Logf("actual secret gate failed: %v; ci=%v adapter=%s type=%s target=%s", err, p.CIJob != nil, op.AdapterID, op.OperationType, op.TargetID)
	}
	return err
}

type ciJobControlDiagnostic struct {
	transport.CIControl
	t *testing.T
}

func (c ciJobControlDiagnostic) Exchange(ctx context.Context, b generated.HostActionBundle, r io.Reader, w io.WriteCloser) error {
	e := c.CIControl.Exchange(ctx, b, r, w)
	if e != nil {
		c.t.Logf("CI exchange: %v", e)
	}
	return e
}
func (c ciJobControlDiagnostic) Finish(ctx context.Context, b generated.HostActionBundle, r generated.HostActionResult) error {
	e := c.CIControl.Finish(ctx, b, r)
	if e != nil {
		c.t.Logf("CI finish: %v", e)
	}
	return e
}

type ciJobFactoryDiagnostic struct {
	ciJobControlFactory
	t *testing.T
}

func (f ciJobFactoryDiagnostic) NewCIControl(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, v []*credentialref.Value) (transport.CIControl, error) {
	c, e := f.ciJobControlFactory.NewCIControl(ctx, op, b, v)
	if e != nil {
		f.t.Logf("CI factory: %v", e)
		return nil, e
	}
	return ciJobControlDiagnostic{c, f.t}, nil
}

type ciJobCredentialFixture struct{ key []byte }

func (f ciJobCredentialFixture) Resolve(_ context.Context, b credentialref.StepBinding) (*credentialref.Value, error) {
	switch b.PurposeID {
	case hostaction.PurposeID:
		return credentialref.NewValue(f.key)
	case store.CIJobRegistrationPurpose:
		return credentialref.NewValue([]byte("admin-synthetic"))
	case store.CIJobObserverPurpose:
		return credentialref.NewValue([]byte("read-synthetic"))
	}
	return nil, actionFailure()
}

type ciJobWireFixture struct {
	allowed    atomic.Int32
	name       string
	fault      string
	beforeHeld func()
}

func (f *ciJobWireFixture) Lookup(id, version string) (hostaction.Handler, bool) {
	return f, id == hostaction.CIJobAction && version == "1.0.0"
}
func (f *ciJobWireFixture) Execute(context.Context, generated.HostActionBundle) (generated.HostActionResult, error) {
	return generated.HostActionResult{}, actionFailure()
}
func (f *ciJobWireFixture) Verify(_ context.Context, b generated.HostActionBundle, r generated.HostActionResult) error {
	d, e := hostaction.BundleDigest(b)
	if e != nil || r.BundleDigest != d || hostaction.ValidateResult(r) != nil {
		return actionFailure()
	}
	return nil
}
func (f *ciJobWireFixture) ExecuteCI(ctx context.Context, b generated.HostActionBundle, input io.ReadCloser, output io.Writer) (generated.HostActionResult, error) {
	var spec cijobrunner.Spec
	if json.Unmarshal([]byte(b.ActionInput), &spec) != nil {
		return generated.HostActionResult{}, actionFailure()
	}
	f.name = spec.RunnerName
	stream := cijobrunner.NewStream(input, output)
	token, e := stream.Registration(ctx)
	if e != nil {
		return generated.HostActionResult{}, e
	}
	if string(token.Bytes()) != "registration-synthetic" {
		token.Close()
		return generated.HostActionResult{}, actionFailure()
	}
	token.Close()
	if e = stream.Configured(ctx, cijobrunner.ConfiguredRunner{Stage: "configured", RunnerID: 40, RunnerName: spec.RunnerName}); e != nil {
		return generated.HostActionResult{}, e
	}
	if f.beforeHeld != nil {
		f.beforeHeld()
	}
	decision, e := stream.Held(ctx)
	if e != nil {
		return generated.HostActionResult{}, e
	}
	if cijobrunner.ValidateDecision(spec.Binding, decision) != nil || decision.Binding.JobID != "70" {
		return generated.HostActionResult{}, actionFailure()
	}
	f.allowed.Add(1)
	event := cijobrunner.LifecycleEvent{Stage: "allowed", Sequence: 1}
	if e = stream.Event(ctx, event); e != nil {
		return generated.HostActionResult{}, e
	}
	logDigest, _ := cijobrunner.LifecycleEventDigest([]cijobrunner.LifecycleEvent{event})
	completion := cijobrunner.Completion{Succeeded: true, Stopped: true, VolumesRemoved: true, LogDigest: logDigest}
	if f.fault == "wrong-log" {
		completion.LogDigest = hostaction.Digest("wrong-log")
	}
	if e = hostaction.WriteFrame(output, struct {
		Kind       string                  `json:"kind"`
		Completion *cijobrunner.Completion `json:"completion"`
	}{"complete", &completion}, 8192); e != nil {
		return generated.HostActionResult{}, e
	}
	bd, _ := hostaction.BundleDigest(b)
	result := generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: bd, Status: "succeeded", Changed: true, EffectObserved: true, Reason: "verified"}
	result.ResultDigest = hostaction.ResultDigest(result)
	return result, nil
}
func TestCIJobApprovedControllerSSH(t *testing.T) {
	for _, fault := range []string{"none", "execute-revoked", "wrong-job", "wrong-log"} {
		t.Run(fault, func(t *testing.T) {
			wire := &ciJobWireFixture{fault: fault}
			hostActionAcceptance(t, "success", hostActionAcceptanceHooks{EnrollmentOnly: true, Peer: func(t *testing.T, k ssh.Signer, s ActionSigner, w *atomic.Int32, d string) int {
				return hostActionAcceptancePeerDispatcher(t, k, s, w, d, wire)
			}, Enrollment: func(t *testing.T, f hostActionEnrollmentFixture) adapter.CredentialResolver {
				testCIJobController(t, f, wire)
				return nil
			}})
		})
	}
}
func testCIJobController(t *testing.T, f hostActionEnrollmentFixture, wire *ciJobWireFixture) {
	t.Helper()
	f.UseWallClock()
	ctx := f.Context
	exec := func(q string, a ...any) {
		t.Helper()
		if _, e := f.DB.Exec(q, a...); e != nil {
			t.Fatal(e)
		}
	}
	grant := func(id, principal, action, cap, kind, target, branch string) {
		exec(`INSERT INTO effective_authorization_grants VALUES(?,?,'control-plane-admin',?,?,?,?,?,1,'active','now','now')`, id, principal, action, cap, kind, target, func() any {
			if branch == "" {
				return nil
			}
			return branch
		}())
	}
	source := generated.CiEnrollmentBinding{Schema: generated.SchemaIDCiEnrollmentBinding, SchemaVersion: "1.0.0", EnrollmentID: "ci-source", OwnerID: "operator-a", BindingID: "source-binding", AdapterID: "scm.github", RepositoryID: "10", RepositoryOwnerID: "20", Repository: "owner/repo", WorkflowID: "30", WorkflowPath: ".github/workflows/ci.yml", WorkflowDigest: hostaction.BytesDigest([]byte("name: CI\n")), Revision: strings.Repeat("a", 40), Ref: "refs/heads/main", Event: "push", JobName: "build", RunnerGroupID: "50", Labels: []string{"isolated", "self-hosted"}}
	policy := store.CIEnrollmentPolicy{Definition: generated.CiEnrollmentDefinition{Schema: generated.SchemaIDCiEnrollmentDefinition, SchemaVersion: "1.0.0", EnrollmentID: source.EnrollmentID, OwnerID: source.OwnerID, BindingID: source.BindingID, BindingDigest: hostaction.Digest(source)}, Binding: source, ResourceKeyDigest: store.CIEnrollmentPolicyKey(source)}
	binding := generated.CiJobExecutionBinding{Schema: generated.SchemaIDCiJobExecutionBinding, SchemaVersion: "1.0.0", BindingID: "ci-runtime", HostID: "synthetic-host", HostIdentityDigest: f.DestinationIdentity, TargetRevision: f.Target.Revision, TargetDigest: f.TargetDigest, AutomationPrincipalID: "automation-a", CallerUID: 1001, SSHReferenceID: "action-key", SSHMaterialVersion: "version-a", RegistrationReferenceID: "registration-key", RegistrationMaterialVersion: "version-a", ObserverReferenceID: "observer-key", ObserverMaterialVersion: "version-a", RuntimeProfileID: "runtime-a", RuntimeDigest: hostaction.Digest("synthetic-protected-profile"), RunnerGroupName: "isolated", MaximumSeconds: 60}
	if e := f.Authority.Close(); e != nil {
		t.Fatal(e)
	}
	authority, e := store.Open(ctx, store.Config{DatabasePath: filepath.Join(f.Directory, "control.db"), Mode: store.OpenExisting, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: time.Now, CIEnrollmentPolicies: []store.CIEnrollmentPolicy{policy}, CIJobBindings: []generated.CiJobExecutionBinding{binding}})
	if e != nil {
		t.Fatal(e)
	}
	defer authority.Close()
	for _, g := range []struct{ id, action, cap, kind, target, branch string }{{"ci-source-read", "read", "ci.enrollment.read", "ci-enrollment", "ci-source", ""}, {"ci-source-prepare", "author", "ci.enrollment.prepare", "ci-enrollment", "ci-source", ""}, {"ci-job-prepare", "author", "ci.job.prepare", "ci-enrollment", "ci-source", ""}, {"ci-source-ack", "acknowledge", "plan.acknowledge", "plan-target", "ci-source", "human"}, {"ci-source-exec", "execute", "ci.enrollment.register", "execution-target", "ci-source", "human"}, {"ci-host-prepare", "author", "host.action.prepare", "host", "synthetic-host", ""}, {"ci-host-exec", "execute", store.CIJobOperation, "execution-target", "synthetic-host", "human"}} {
		grant(g.id, "operator-a", g.action, g.cap, g.kind, g.target, g.branch)
	}
	exec(`INSERT INTO effective_authorization_principals VALUES('automation-a','agent','active',1,'now','now')`)
	grant("ci-automation", "automation-a", "execute", store.CIJobOperation, "execution-target", "synthetic-host", "human")
	for i, ref := range []struct{ id, purpose string }{{"action-key", hostaction.PurposeID}, {"registration-key", store.CIJobRegistrationPurpose}, {"observer-key", store.CIJobObserverPurpose}} {
		exec(`INSERT INTO credential_reference_versions VALUES(?,?,'host-action',?,'synthetic-host','native-systemd','version-a',?,'active',1,0,?,?,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, fmt.Sprintf("ci-version-%d", i), ref.id, ref.purpose, hostaction.Digest("synthetic"), time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), []byte(`["host-action"]`), hostaction.Digest("synthetic"))
	}
	revisions := store.NewPlanRepository(authority)
	declarations, e := change.NewService(store.NewDeclarationRepository(authority), time.Now)
	if e != nil {
		t.Fatal(e)
	}
	observations, _ := planengine.NewStateObservationReader(revisions)
	plans, e := planengine.NewService(planengine.Config{Repository: revisions, Observations: observations, Clock: time.Now, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "infrastructure", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if e != nil {
		t.Fatal(e)
	}
	ackRepo := store.NewAcknowledgementRepository(authority)
	ack, e := acknowledgement.NewService(acknowledgement.Config{Repository: ackRepo, Plans: lifecycleAcceptancePlanReader{plans}, Authorizer: authorization.NewEvaluator(store.NewEffectiveAuthorizationRepository(authority)), Clock: time.Now})
	if e != nil {
		t.Fatal(e)
	}
	enrollments := store.NewCIEnrollmentRepository(authority)
	registry := adapter.NewRegistry()
	core := runengine.CoreRouter{CIEnrollment: &runengine.CIEnrollmentEffect{Repository: enrollments, Approvals: ackRepo}}
	gates := store.NewGateRepository(authority)
	jobs := store.NewCIJobRepository(authority)
	jobs.ConfigureAdmission(gates, ciJobSnapshotFixture{gates})
	provider := ciJobProviderFixture(t, wire)
	sourceResolver := ciJobExecutionSource{hosts: store.NewHostActionRepository(authority), jobs: jobs}
	signedAuthority, e := newHostActionAuthority(sourceResolver, f.Signer, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	impl, e := transport.New(hostActionTargets{repository: sourceResolver, allowed: []string{f.DestinationIdentity}}, &HostActionBundleIssuer{Repository: sourceResolver, Signer: f.Signer, Clock: time.Now}, signedAuthority)
	if e != nil {
		t.Fatal(e)
	}
	if e = impl.ConfigureCI(ciJobFactoryDiagnostic{ciJobControlFactory{jobs: jobs, provider: provider}, t}); e != nil {
		t.Fatal(e)
	}
	if e = registry.Register("host-action", impl); e != nil {
		t.Fatal(e)
	}
	if e = registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: "host-action", ProfileID: "synthetic-profile", CapabilityID: "synthetic-capability", Enabled: true}, ciJobCredentialFixture{f.Key}); e != nil {
		t.Fatal(e)
	}
	engine, e := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(authority), Plans: plans, Admission: runengine.NewAdmissionGate(ack, time.Now), Adapters: registry, Core: core, SecretGate: ciJobGateDiagnostic{t, hostActionGate{jobs: jobs, allowed: []string{f.DestinationIdentity}}}, CredentialStep: &runengine.CredentialStep{Bindings: store.NewCredentialRepository(authority), Resolvers: registry, Profiles: hostActionAcceptanceProfile{}, Plans: plans, Clock: time.Now}, Clock: time.Now})
	if e != nil {
		t.Fatal(e)
	}
	apply := func(d generated.DeclarationRevision) (generated.Run, generated.Plan) {
		t.Helper()
		prep, e := plans.Prepare(ctx, d.DeclarationID, d.Revision)
		if e != nil {
			t.Fatal(e)
		}
		created, e := plans.Create(ctx, planengine.AuthorScope{PrincipalID: "operator-a", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "ci-session"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: d.DeclarationID, DeclarationRevision: d.Revision, ExpectedStateRevision: prep.ExpectedStateRevision, RecoveryEpoch: prep.RecoveryEpoch, ObservationFingerprint: prep.ObservationFingerprint, IdempotencyKey: "plan-" + d.DeclarationID, Extensions: d.Extensions})
		if e != nil {
			t.Fatal(e)
		}
		p := created.Plan
		human := identity.Principal{ID: "operator-a", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
		card, e := ack.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: "ci-nonce-" + d.DeclarationID}, p.PlanID)
		if e != nil {
			t.Fatal(e)
		}
		approved := hostActionAcceptanceSlackApproval(t, ack, card)
		branch := "human"
		decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-" + d.DeclarationID, PrincipalID: "operator-a", Action: "execute", TargetID: authorization.ExecutionResourceIDs(p, p.Operations[0])[0], Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, PlanDigest: p.PlanDigest, DecidedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
		if p.CIJob != nil {
			if checkErr := jobs.ValidatePlan(context.Background(), p); store.Code(checkErr) != generated.ErrorCodeAuthorizationDenied {
				t.Fatalf("missing durable running step/lease accepted: %v", checkErr)
			}
			if checkErr := jobs.ValidatePlan(ctx, p); checkErr != nil {
				t.Fatalf("CI job pre-submit gate: %v", checkErr)
			}
		}
		run, e := engine.Submit(ctx, runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, IdempotencyKey: "run-" + d.DeclarationID, Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: audit.Attribution{AuthenticatedPrincipalID: "operator-a", AuthenticatedPrincipalMethod: identity.LocalOSPeerMethod, ResponsibleHumanPrincipalID: &human.ID}})
		if e != nil && (p.CIJob == nil || wire.fault == "none") {
			t.Fatalf("submit: %v run=%+v name=%s allowed=%d", e, run, wire.name, wire.allowed.Load())
		}
		return run, p
	}
	current, _ := revisions.CurrentRevision(ctx)
	prepared, e := enrollments.Prepare(ctx, generated.CiEnrollmentDraftRequest{Schema: generated.SchemaIDCiEnrollmentDraftRequest, SchemaVersion: "1.0.0", EnrollmentID: source.EnrollmentID, BindingID: source.BindingID, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: "enroll-ci", ReasonDigest: hostaction.Digest("reason")})
	if e != nil {
		t.Fatal(e)
	}
	draft, e := enrollments.Stage(ctx, prepared)
	if e != nil {
		t.Fatal(e)
	}
	enrolled, e := declarations.Revise(ctx, change.AuthorScope{PrincipalID: "operator-a", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "ci-session"}, draft)
	if e != nil {
		t.Fatal(e)
	}
	registered, _ := apply(enrolled.Document)
	if registered.Status != "succeeded" {
		t.Fatal("actual enrollment failed", registered)
	}
	app, e := api.NewApplication(api.Config{Authority: authority, Authorizer: store.NewReadAuthorizer(authority), Reads: store.NewReadRepository(authority), Results: f.Results})
	if e != nil {
		t.Fatal(e)
	}
	policyRepo := store.NewEffectiveAuthorizationRepository(authority)
	if e = api.RegisterDeclarationPlanOperations(app, api.DeclarationPlanConfig{Declarations: declarations, Plans: plans, Results: f.Results, Authorization: api.EffectiveAuthorizationConfig{Authorizer: authorization.NewEvaluator(policyRepo), Recorder: policyRepo, WorkflowOwners: authority, Clock: time.Now}}); e != nil {
		t.Fatal(e)
	}
	if e = api.RegisterCIJobOperations(app, api.CIJobOperations{Jobs: jobs, Declarations: declarations, Credentials: store.NewCredentialRepository(authority), Results: f.Results, Prepare: jobs.Prepare}); e != nil {
		t.Fatal(e)
	}
	current, _ = revisions.CurrentRevision(ctx)
	input := generated.CiJobDraftRequest{Schema: generated.SchemaIDCiJobDraftRequest, SchemaVersion: "1.0.0", EnrollmentID: source.EnrollmentID, ExecutionBindingID: binding.BindingID, RunID: "60", Attempt: 2, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: "ci-job", ReasonDigest: hostaction.Digest("job-reason")}
	raw, _ := json.Marshal(input)
	request := httptest.NewRequest("POST", "/api/v1/ci/jobs/drafts", bytes.NewReader(raw)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatal("job draft", response.Code, response.Body.String())
	}
	var envelope struct {
		Data generated.DeclarationRevision `json:"data"`
	}
	if e = json.Unmarshal(response.Body.Bytes(), &envelope); e != nil || envelope.Data.CIJob == nil {
		t.Fatal(response.Body.String(), e)
	}
	if bytes.Contains(response.Body.Bytes(), []byte("owner/repo")) {
		t.Fatal("private policy exposed")
	}
	if wire.fault == "execute-revoked" {
		wire.beforeHeld = func() {
			exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='ci-host-exec'`)
		}
	}
	run, p := apply(envelope.Data)
	if wire.fault == "none" {
		if run.Status != "succeeded" || wire.allowed.Load() != 1 {
			t.Fatal("exact controller flow failed", run, wire.allowed.Load())
		}
		var consumed int
		var cleanup, job, completion string
		if e = f.DB.QueryRow(`SELECT admission_consumed,cleanup_status,job_id,completion_digest FROM ci_job_executions WHERE run_id=?`, run.RunID).Scan(&consumed, &cleanup, &job, &completion); e != nil || consumed != 1 || cleanup != "verified" || job != "70" || completion == "" {
			t.Fatal("durable admission/receipt", consumed, cleanup, job, e)
		}
		if checkErr := jobs.ValidatePlan(context.Background(), p); store.Code(checkErr) != generated.ErrorCodeAuthorizationDenied {
			t.Fatalf("completed run restored execution authority: %v", checkErr)
		}
		// A consumed completed plan/run never becomes another allow after replay.
		var lease string
		f.DB.QueryRow(`SELECT lease_id FROM ci_job_executions WHERE run_id=?`, run.RunID).Scan(&lease)
		if e = jobs.ConsumeAdmission(ctx, adapter.Operation{}, adapter.ExactExecutionBinding{PlanID: p.PlanID, RunID: run.RunID, StepID: run.Steps[0].StepID, LeaseID: lease}, ciObservationFixture()); store.Code(e) != generated.ErrorCodeStateConflict {
			t.Fatal("replayed admission accepted")
		}
	} else {
		if run.Status == "succeeded" {
			t.Fatal("denied controller flow succeeded", wire.fault, run)
		}
		if wire.fault != "wrong-log" && wire.allowed.Load() != 0 {
			t.Fatal("denied job released", wire.fault)
		}
	}
}
func ciJobProviderFixture(t *testing.T, wire *ciJobWireFixture) *githubci.Client {
	t.Helper()
	runnerReads := 0
	repo := func() map[string]any {
		return map[string]any{"id": 10, "name": "repo", "full_name": "owner/repo", "owner": map[string]any{"id": 20, "login": "owner"}}
	}
	runner := func(offline bool) map[string]any {
		status, busy := "online", true
		if offline {
			status, busy = "offline", false
		}
		return map[string]any{"id": 40, "name": wire.name, "os": "linux", "status": status, "busy": busy, "labels": []any{map[string]any{"name": "isolated"}, map[string]any{"name": "self-hosted"}}}
	}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body any
		switch r.Method + " " + r.URL.Path {
		case "GET /orgs/owner":
			body = map[string]any{"id": 20, "login": "owner"}
		case "GET /repos/owner/repo":
			body = repo()
		case "GET /orgs/owner/actions/runner-groups/50":
			body = map[string]any{"id": 50, "name": "isolated", "visibility": "selected"}
		case "GET /orgs/owner/actions/runner-groups/50/repositories":
			body = map[string]any{"total_count": 1, "repositories": []any{repo()}}
		case "GET /orgs/owner/actions/runner-groups/50/runners":
			body = map[string]any{"total_count": 1, "runners": []any{runner(false)}}
		case "GET /orgs/owner/actions/runners/40":
			runnerReads++
			body = runner(runnerReads >= 3)
		case "POST /orgs/owner/actions/runners/registration-token":
			if r.Header.Get("Authorization") != "Bearer admin-synthetic" {
				t.Error("registration credential scope")
			}
			w.WriteHeader(201)
			body = map[string]any{"token": "registration-synthetic", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
		case "DELETE /orgs/owner/actions/runners/40":
			if runnerReads < 3 {
				t.Error("cleanup before owned stop")
			}
			w.WriteHeader(204)
			return
		case "GET /repos/owner/repo/actions/runs/60", "GET /repos/owner/repo/actions/runs/60/attempts/2":
			body = map[string]any{"id": 60, "run_attempt": 2, "workflow_id": 30, "path": ".github/workflows/ci.yml", "head_sha": strings.Repeat("a", 40), "head_branch": "main", "event": "push", "status": "in_progress", "repository": repo(), "head_repository": repo()}
		case "GET /repos/owner/repo/actions/runs/60/attempts/2/jobs":
			name := "build"
			if wire.fault == "wrong-job" {
				name = "untrusted"
			}
			body = map[string]any{"total_count": 1, "jobs": []any{map[string]any{"id": 70, "run_id": 60, "head_sha": strings.Repeat("a", 40), "name": name, "status": "in_progress", "runner_id": 40, "runner_group_id": 50, "labels": []string{"isolated", "self-hosted"}}}}
		case "GET /repos/owner/repo/contents/.github/workflows/ci.yml":
			body = map[string]any{"type": "file", "path": ".github/workflows/ci.yml", "size": 9, "encoding": "base64", "content": "bmFtZTogQ0kK"}
		default:
			t.Error("unexpected provider route", r.Method, r.URL.String())
			w.WriteHeader(404)
			return
		}
		if e := json.NewEncoder(w).Encode(body); e != nil {
			t.Error(e)
		}
	}))
	t.Cleanup(s.Close)
	client, e := githubci.NewClient(s.URL, s.Client().Transport)
	if e != nil {
		t.Fatal(e)
	}
	return client
}
func ciObservationFixture() ci.Observation {
	return ci.Observation{RunID: "60", JobID: "70", Binding: ci.Binding{RunnerID: "40"}}
}
