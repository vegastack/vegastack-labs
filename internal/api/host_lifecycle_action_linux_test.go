//go:build linux

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// lifecycleOS substitutes the external host only. A harmless temporary observation
// exercises ordinary action collection; role observations use the existing finite
// synthetic OS producer and real result recorder.
type lifecycleOS struct {
	*roleTestOS
	path          string
	ordinary      bool
	ordinaryCalls int
}

func (o *lifecycleOS) ExecuteBoundWithCredentials(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, v []*credentialref.Value) (adapter.Effect, error) {
	current, e := o.hosts.CurrentExecution(ctx, op, b)
	if e != nil {
		return adapter.Effect{}, e
	}
	o.ordinary = current.Draft.Request.ActionID == "debian.access.collect"
	if !o.ordinary {
		return o.roleTestOS.ExecuteBoundWithCredentials(ctx, op, b, v)
	}
	if len(v) != 1 {
		return adapter.Effect{}, fmt.Errorf("missing credential")
	}
	o.binding = b
	o.ordinaryCalls++
	body, e := os.ReadFile(o.path)
	if e != nil {
		return adapter.Effect{}, e
	}
	return adapter.Effect{Status: "succeeded", Changed: false, EffectObserved: true, ResultDigest: hostaction.BytesDigest(body)}, nil
}
func (o *lifecycleOS) Verify(ctx context.Context, op adapter.Operation, e adapter.Effect) (adapter.Verification, error) {
	if !o.ordinary {
		return o.roleTestOS.Verify(ctx, op, e)
	}
	b, err := os.ReadFile(o.path)
	return adapter.Verification{Verified: err == nil && hostaction.BytesDigest(b) == e.ResultDigest, Digest: hostaction.BytesDigest(b)}, err
}

func lifecycleApplyRole(t *testing.T, f roleAdmissionFixture, at *time.Time, target generated.HostDiscoveryTargetDraftRequest, desired generated.LinuxRoleInput, transport lifecycleBrowserTransport) generated.Plan {
	t.Helper()
	clock := func() time.Time { return *at }
	readiness := roleTestReadiness{f.repo, clock}
	policy := store.NewEffectiveAuthorizationRepository(f.authority)
	evaluator := authorization.NewEvaluator(policy)
	n := 0
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "1.0.0", ReleaseBuildID: "build-a"}, func() (string, error) { n++; return fmt.Sprintf("linked-action-%d", n), nil })
	app, e := NewApplication(Config{Authority: f.authority, Authorizer: store.NewReadAuthorizer(f.authority), Reads: store.NewReadRepository(f.authority), Results: factory, Cursors: testCursor{}})
	if e != nil {
		t.Fatal(e)
	}
	auth := EffectiveAuthorizationConfig{WorkflowOwners: f.authority, Authorizer: evaluator, Recorder: policy, Clock: clock}
	app.effective = auth
	serve := transport(app, f.authority, f.db, *at)
	declarations, e := change.NewService(store.NewDeclarationRepository(f.authority), clock)
	if e != nil {
		t.Fatal(e)
	}
	hosts := store.NewHostActionRepository(f.authority)
	credentials := store.NewCredentialRepository(f.authority)
	revisions := store.NewPlanRepository(f.authority)
	observations, e := planengine.NewStateObservationReader(revisions)
	if e != nil {
		t.Fatal(e)
	}
	plans, e := planengine.NewService(planengine.Config{HostActions: hosts, HostActionCredentials: credentials, Repository: revisions, Observations: observations, Clock: clock, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "infrastructure", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if e != nil {
		t.Fatal(e)
	}
	ack, e := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(f.authority), Plans: roleTestPlans{plans}, Authorizer: evaluator, Clock: clock})
	if e != nil {
		t.Fatal(e)
	}
	runs := store.NewRunRepository(f.authority)
	runs.ConfigureHostRoles(f.repo, readiness)
	osBoundary := &lifecycleOS{roleTestOS: &roleTestOS{authority: f.authority, hosts: hosts, clock: clock}, path: filepath.Join(t.TempDir(), "synthetic-host-state")}
	if err := os.WriteFile(osBoundary.path, []byte("synthetic-access-observation"), 0600); err != nil {
		t.Fatal(err)
	}
	registry := adapter.NewRegistry()
	if e = registry.Register(hostaction.AdapterID, osBoundary); e != nil {
		t.Fatal(e)
	}
	if e = registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: hostaction.AdapterID, ProfileID: "synthetic-role-profile", CapabilityID: "synthetic-role-ssh", Enabled: true}, roleTestCredential{}); e != nil {
		t.Fatal(e)
	}
	engine, e := runengine.NewEngine(runengine.Config{Repository: runs, Plans: plans, Admission: runengine.NewAdmissionGate(ack, clock), Adapters: registry, SecretGate: roleTestSecretGate{hosts}, CredentialStep: &runengine.CredentialStep{Bindings: credentials, Resolvers: registry, Profiles: roleTestCredential{}, Plans: plans, Clock: clock}, Clock: clock})
	if e != nil {
		t.Fatal(e)
	}
	for _, err := range []error{RegisterHostActionOperations(app, HostActionOperations{Hosts: hosts, Declarations: declarations, Credentials: credentials, RolePreparer: readiness, Results: factory}), RegisterDeclarationPlanOperations(app, DeclarationPlanConfig{Declarations: declarations, Plans: plans, Results: factory, Authorization: auth}), RegisterRunOperations(app, RunOperationConfig{Runs: engine, Plans: revisions, Acknowledgements: ack, Results: factory, Authorization: auth})} {
		if err != nil {
			t.Fatal(err)
		}
	}
	f.seed.exec(`INSERT INTO effective_authorization_principals VALUES('linked-automation','agent','active',1,'now','now')`)
	f.seed.exec(`INSERT OR IGNORE INTO effective_authorization_grants VALUES('linked-automation','linked-automation','infrastructure-admin','execute','host.action.execute','execution-target',?,'human',1,'active','now','now')`, f.input.HostID)
	grant := func(id, action, cap, kind, target string, branch any) {
		f.seed.exec(`INSERT OR IGNORE INTO effective_authorization_grants VALUES(?,'human-a','control-plane-admin',?,?,?,?,?,1,'active','now','now')`, "linked-"+id, action, cap, kind, target, branch)
	}
	grant("prepare", "author", "host.action.prepare", "host", f.input.HostID, nil)
	grant("execute", "execute", "host.action.execute", "execution-target", f.input.HostID, "human")
	grant("ack", "acknowledge", "plan.acknowledge", "plan-target", f.input.HostID, "human")
	d := hostaction.Digest("synthetic-linked-action-key")
	f.seed.exec(`INSERT INTO credential_reference_versions VALUES('linked-role-key','linked-role-key','host-action','host-action-ssh',?,'native-systemd','version-a',?,'active',1,0,?,?,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','human-a','now')`, f.input.HostID, d, at.Format(time.RFC3339), []byte(`["host-action"]`), d)
	registerLifecycleBrowserApproval(t, app, ack, plans, factory)
	post := func(path string, in, out any) {
		t.Helper()
		w := serve(http.MethodPost, path, in)
		if w.Code != 200 {
			t.Fatalf("linked action %s: %d %s", path, w.Code, w.Body.String())
		}
		var envelope struct{ Data json.RawMessage }
		if json.Unmarshal(w.Body.Bytes(), &envelope) != nil || json.Unmarshal(envelope.Data, out) != nil {
			t.Fatal("linked action response")
		}
	}
	var final generated.Plan
	for _, action := range []string{"debian.access.collect", "debian.role.apply"} {
		rev, e := revisions.CurrentRevision(f.ctx)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(f.input)
		if action == "debian.role.apply" {
			desired.BaselineSnapshotDigest = ""
			desired.CurrentRoleBindingDigest = ""
			desired.ControlIDs = []string{"linux.role-identity-paths"}
			desired.RoleBindingDigest = linuxrole.RoleBindingDigest(desired)
			desired.RenderedPolicyDigest = linuxrole.PolicyDigest(desired)
			raw, _ = json.Marshal(desired)
		}
		req := generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", HostID: f.input.HostID, TargetRevision: 1, TargetDigest: hostaction.Digest(target), ActionID: action, ActionVersion: "1.0.0", ActionInput: string(raw), ActionInputDigest: hostaction.BytesDigest(raw), AutomationPrincipalID: "linked-automation", CallerUID: 1001, CredentialReferenceID: "linked-role-key", CredentialMaterialVersion: "version-a", ExpectedStateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch, IdempotencyKey: action, ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: hostaction.Digest(target), HostIdentityDigest: f.input.HostIdentityDigest}}
		var submission generated.HostActionSubmission
		post("/api/v1/host-actions/draft", req, &submission)
		if submission.OriginalRequestDigest != hostaction.Digest(req) {
			t.Fatal("action response lost original request binding")
		}
		if action == "debian.role.apply" && submission.ContentDigest == submission.OriginalRequestDigest {
			t.Fatal("server role sealing did not preserve distinct original and rendered request digests")
		}
		doc, e := declarations.Get(f.ctx, submission.DeclarationID, 1)
		if e != nil {
			t.Fatal(e)
		}
		rev, e = revisions.CurrentRevision(f.ctx)
		if e != nil {
			t.Fatal(e)
		}
		fp, e := observations.CurrentFingerprint(f.ctx, doc.DeclarationID, doc.Operations)
		if e != nil {
			t.Fatal(e)
		}
		var presentation generated.PlanPresentation
		post("/api/v1/declarations/"+doc.DeclarationID+"/plans", generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: doc.DeclarationID, DeclarationRevision: 1, ExpectedStateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch, ObservationFingerprint: fp, IdempotencyKey: "plan-" + action, Extensions: doc.Extensions}, &presentation)
		p := presentation.Plan
		*at = time.Now().UTC().Truncate(time.Second)
		var approval generated.ApprovalStatus
		post("/api/v1/plans/"+p.PlanID+"/approval-request", generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, RecoveryEpoch: p.Binding.RecoveryEpoch, IdempotencyKey: "approve-" + action, Extensions: []generated.ContractExtension{}}, &approval)
		if approval.Status != "approved" || !approval.AuthorizationCurrent || !approval.CanApply {
			t.Fatal("resource-scoped approval failed", approval)
		}
		var result generated.RunPresentation
		post("/api/v1/plans/"+p.PlanID+"/execute", generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, RecoveryEpoch: p.Binding.RecoveryEpoch, IdempotencyKey: "execute-" + action, Extensions: []generated.ContractExtension{}}, &result)
		assertLifecycleDurableRun(t, f.db, p, result.Run)
		if result.Run.Status != "succeeded" {
			t.Fatalf("linked action failed %+v", result)
		}
		final = p
	}
	if osBoundary.calls != 1 || osBoundary.ordinaryCalls != 1 {
		t.Fatalf("external boundary counts role=%d action=%d", osBoundary.calls, osBoundary.ordinaryCalls)
	}
	return final
}
