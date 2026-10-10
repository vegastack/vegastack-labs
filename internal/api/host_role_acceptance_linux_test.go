//go:build linux

package api

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// Software integration: canonical synthetic prior baseline/native-provenance rows
// are deliberately test-only. Actual SQLite, HTTP draft, policy, plan, single-use
// Slack-method acknowledgement, reservation, run and full-result receipt joins run
// unchanged. Only target OS/SSH and its prequalified credential are substituted.
func TestLinuxRoleApprovedPipeline(t *testing.T) {
	for _, mode := range []string{"success", "missing-baseline", "stale-baseline", "revoked-grant", "baseline-drift-before-run"} {
		t.Run(mode, func(t *testing.T) {
			at := time.Now().UTC().Truncate(time.Second)
			if mode == "success" {
				// Exercise a frozen fixture clock older than the real lease window.
				// Fixture setup must not consume a newly issued execution lease.
				at = at.Add(-2 * time.Minute)
			}
			clock := func() time.Time { return at }
			f := newRoleAdmissionFixture(t, &at)
			readiness := roleTestReadiness{f.repo, clock}
			baseline, e := readiness.snapshot(f.ctx, f.input.HostID, true)
			if e != nil {
				t.Fatal("baseline seed", e)
			}
			if baseline.Profile.RoleID != "host" || baseline.RoleBindingDigest != "" {
				t.Fatal("fixture already installed a role")
			}
			// The default production repository has no synthetic provenance hook.
			unavailable := roleTestReadiness{store.NewGateRepository(f.authority), clock}
			if _, e = unavailable.snapshot(f.ctx, f.input.HostID, true); e == nil {
				t.Fatal("unproven production baseline passed")
			}
			in := roleTestInput(t, f.input)
			in.BaselineSnapshotDigest = ""
			if mode == "missing-baseline" {
				delete(f.proofs.proofs, "native-baseline")
			}
			if mode == "stale-baseline" {
				in.BaselineSnapshotDigest = hostaction.Digest("outdated-snapshot")
			}
			policy := store.NewEffectiveAuthorizationRepository(f.authority)
			evaluator := authorization.NewEvaluator(policy)
			requestNumber := 0
			factory := result.NewFactory(result.BuildInfo{ToolVersion: "1.0.0", ReleaseBuildID: "build-a"}, func() (string, error) { requestNumber++; return fmt.Sprintf("role-test-%d", requestNumber), nil })
			app, e := NewApplication(Config{Authority: f.authority, Authorizer: allowOperationAuthorizer(), Reads: testReads{}, Results: factory, Cursors: testCursor{}})
			if e != nil {
				t.Fatal(e)
			}
			app.effective = EffectiveAuthorizationConfig{Authorizer: evaluator, Recorder: policy, Clock: clock}
			declarations, e := change.NewService(store.NewDeclarationRepository(f.authority), clock)
			if e != nil {
				t.Fatal(e)
			}
			hosts := store.NewHostActionRepository(f.authority)
			credentials := store.NewCredentialRepository(f.authority)
			if e = RegisterHostActionOperations(app, HostActionOperations{Hosts: hosts, Declarations: declarations, Credentials: credentials, RolePreparer: readiness, Results: factory}); e != nil {
				t.Fatal(e)
			}
			seed := f.seed
			seed.exec(`INSERT INTO effective_authorization_principals VALUES('automation-a','agent','active',1,'now','now')`)
			seed.exec(`INSERT INTO effective_authorization_grants VALUES('role-automation','automation-a','infrastructure-admin','execute','host.action.execute','execution-target',?,'human',1,'active','now','now')`, in.HostID)
			grant := func(id, action, cap, kind, target string, branch any) {
				seed.exec(`INSERT INTO effective_authorization_grants VALUES(?,'human-a','control-plane-admin',?,?,?,?,?,1,'active','now','now')`, id, action, cap, kind, target, branch)
			}
			grant("role-prepare", "author", "host.action.prepare", "host", in.HostID, nil)
			d := hostaction.Digest("synthetic-role-credential")
			seed.exec(`INSERT INTO credential_reference_versions VALUES('role-active','role-key','host-action','host-action-ssh',?,'native-systemd','version-a',?,'active',1,0,?,?,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','human-a','now')`, in.HostID, d, at.Format(time.RFC3339), []byte(`["host-action"]`), d)
			inputRaw, _ := json.Marshal(in)
			target := admissionTargetDraft(f.input, in.HostID)
			targetDigest := hostaction.Digest(target)
			req := generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", ActionID: "debian.role.apply", ActionVersion: "1.0.0", ActionInput: string(inputRaw), ActionInputDigest: hostaction.BytesDigest(inputRaw), HostID: in.HostID, TargetRevision: 1, TargetDigest: targetDigest, AutomationPrincipalID: "automation-a", CallerUID: in.AutomationUID, CredentialReferenceID: "role-key", CredentialMaterialVersion: "version-a", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: targetDigest, HostIdentityDigest: in.HostIdentityDigest}, ExpectedStateRevision: 100, IdempotencyKey: "role-apply"}
			// Server sealing changes the draft digest; precompute only to assign the exact
			// declaration-author grant. HTTP still performs the actual readiness check.
			prepared, pe := readiness.PrepareRole(f.ctx, req.ActionID, in)
			if pe == nil {
				if err := linuxrole.ValidateInput(prepared); err != nil {
					t.Fatalf("synthetic prepared input invalid: %v affected=%v", err, prepared.AffectedBaselineControlIDs)
				}
				b, _ := json.Marshal(prepared)
				sealed := req
				sealed.ActionInput = string(b)
				sealed.ActionInputDigest = hostaction.BytesDigest(b)
				grant("role-author", "author", "declaration.author", "declaration", hostaction.DraftID(sealed), nil)
			}
			if pe != nil && mode != "missing-baseline" && mode != "stale-baseline" {
				t.Fatalf("prepare role: %v", pe)
			}
			w := serveGateRequest(t, app, http.MethodPost, "/api/v1/host-actions/draft", req)
			if mode == "missing-baseline" || mode == "stale-baseline" {
				if w.Code == http.StatusOK {
					t.Fatal("unready role draft accepted")
				}
				return
			}
			if w.Code != http.StatusOK {
				t.Fatalf("draft HTTP%d %s", w.Code, w.Body.String())
			}
			var submitted struct {
				Data generated.HostActionSubmission
			}
			if json.Unmarshal(w.Body.Bytes(), &submitted) != nil {
				t.Fatal("draft response")
			}
			revisions := store.NewPlanRepository(f.authority)
			observations, e := planengine.NewStateObservationReader(revisions)
			if e != nil {
				t.Fatal(e)
			}
			plans, e := planengine.NewService(planengine.Config{HostActions: hosts, HostActionCredentials: credentials, Repository: revisions, Observations: observations, Clock: clock, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "infrastructure", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
			if e != nil {
				t.Fatal(e)
			}
			doc, e := declarations.Get(f.ctx, submitted.Data.DeclarationID, 1)
			if e != nil {
				t.Fatal(e)
			}
			current, e := revisions.CurrentRevision(f.ctx)
			if e != nil {
				t.Fatal(e)
			}
			finger, e := observations.CurrentFingerprint(f.ctx, doc.DeclarationID, doc.Operations)
			if e != nil {
				t.Fatal(e)
			}
			made, e := plans.Create(f.ctx, planengine.AuthorScope{PrincipalID: "human-a", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "role-integration"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: doc.DeclarationID, DeclarationRevision: 1, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, ObservationFingerprint: finger, IdempotencyKey: "role-plan", Extensions: doc.Extensions})
			if e != nil {
				t.Fatal("plan", e)
			}
			p := made.Plan
			if p.HostRoleScope == nil || p.HostRoleScope.CurrentRoleBindingDigest != "" || p.HostRoleScope.RoleBindingDigest != in.RoleBindingDigest {
				t.Fatal("wrong initial role scope")
			}
			grant("role-execute", "execute", "host.action.execute", "execution-target", in.HostID, "human")
			grant("role-ack", "acknowledge", "plan.acknowledge", "plan-target", in.HostID, "human")
			ack, e := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(f.authority), Plans: roleTestPlans{plans}, Authorizer: evaluator, Clock: clock})
			if e != nil {
				t.Fatal(e)
			}
			human := identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
			card, e := ack.Request(f.ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: "role-one-time-nonce"}, p.PlanID)
			if e != nil {
				t.Fatal("ack request", e)
			}
			slackHuman := human
			slackHuman.Method = identity.SlackSocketModeMethod
			expires, _ := time.Parse(time.RFC3339, card.Request.ExpiresAt)
			approved, e := ack.Decide(f.ctx, acknowledgement.Candidate{Human: slackHuman, AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove, PlanID: p.PlanID, PlanDigest: p.PlanDigest, TargetDigest: card.Request.TargetDigest, ReasonDigest: card.Request.ReasonDigest, Nonce: card.Nonce, StateRevision: card.Request.StateRevision, RecoveryEpoch: card.Request.RecoveryEpoch, ExpiresAt: expires, DecidedAt: at})
			if e != nil {
				t.Fatal("Slack candidate", e)
			}
			runs := store.NewRunRepository(f.authority)
			runs.ConfigureHostRoles(f.repo, readiness)
			targetOS := &roleTestOS{authority: f.authority, hosts: hosts, clock: clock}
			registry := adapter.NewRegistry()
			if e = registry.Register(hostaction.AdapterID, targetOS); e != nil {
				t.Fatal(e)
			}
			if e = registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: hostaction.AdapterID, ProfileID: "synthetic-role-profile", CapabilityID: "synthetic-role-ssh", Enabled: true}, roleTestCredential{}); e != nil {
				t.Fatal(e)
			}
			engine, e := runengine.NewEngine(runengine.Config{Repository: runs, Plans: plans, Admission: runengine.NewAdmissionGate(ack, clock), Adapters: registry, SecretGate: roleTestSecretGate{hosts}, CredentialStep: &runengine.CredentialStep{Bindings: credentials, Resolvers: registry, Profiles: roleTestCredential{}, Plans: plans, Clock: clock}, Clock: clock, LeaseContext: func(ctx context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
				return context.WithTimeout(ctx, deadline.Sub(clock()))
			}})
			if e != nil {
				t.Fatal(e)
			}
			branch := "human"
			decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "role-decision", PrincipalID: human.ID, Action: "execute", TargetID: in.HostID, Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, PlanDigest: p.PlanDigest, DecidedAt: at.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
			if mode == "baseline-drift-before-run" {
				delete(f.proofs.proofs, "native-baseline")
			}
			if mode == "revoked-grant" {
				seed.exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='role-automation'`)
			}
			applied, e := engine.Submit(f.ctx, runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, IdempotencyKey: "run-role", Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: audit.Attribution{AuthenticatedPrincipalID: human.ID, AuthenticatedPrincipalMethod: human.Method, ResponsibleHumanPrincipalID: &human.ID}})
			if mode == "revoked-grant" || mode == "baseline-drift-before-run" {
				if e == nil && applied.Status == "succeeded" || targetOS.calls != 0 {
					t.Fatalf("revoked grant executed: %+v %v", applied, e)
				}
				return
			}
			if e != nil || applied.Status != "succeeded" || targetOS.calls != 1 {
				t.Fatalf("role execution run=%+v error=%v calls=%d", applied, e, targetOS.calls)
			}
			after, e := f.repo.ResolveHostAdmission(f.ctx, in.HostID)
			if e != nil {
				t.Fatal(e)
			}
			if after.RoleBindingDigest != in.RoleBindingDigest || after.Profile.RoleID != "control" {
				t.Fatalf("role not installed: %+v", after)
			}
			if _, e = readiness.snapshot(f.ctx, in.HostID, true); e == nil {
				t.Fatal("old baseline survived role mutation")
			}
			collected, e := readiness.snapshot(f.ctx, in.HostID, false)
			if e != nil || collected.RoleBindingDigest != in.RoleBindingDigest {
				t.Fatal("post-role recollection inaccessible", e)
			}
			for _, r := range after.Results {
				if r.ProducerID == "linux-role" && r.QualificationDigest != nil {
					t.Fatal("software invented native qualification")
				}
			}
			// Recollection has a fresh draft, plan, acknowledgement and lease. It
			// remains available after role effects invalidate the old baseline.
			in.CurrentRoleBindingDigest = after.RoleBindingDigest
			in.BaselineSnapshotDigest = ""
			req.ActionID = "debian.role.collect"
			req.IdempotencyKey = "role-collect"
			current, e = revisions.CurrentRevision(f.ctx)
			if e != nil {
				t.Fatal(e)
			}
			req.ExpectedStateRevision = current.StateRevision
			inputRaw, _ = json.Marshal(in)
			req.ActionInput = string(inputRaw)
			req.ActionInputDigest = hostaction.BytesDigest(inputRaw)
			prepared, e = readiness.PrepareRole(f.ctx, req.ActionID, in)
			if e != nil {
				t.Fatal("collect preparation", e)
			}
			sealed := req
			b, _ := json.Marshal(prepared)
			sealed.ActionInput = string(b)
			sealed.ActionInputDigest = hostaction.BytesDigest(b)
			grant("role-author-collect", "author", "declaration.author", "declaration", hostaction.DraftID(sealed), nil)
			w = serveGateRequest(t, app, http.MethodPost, "/api/v1/host-actions/draft", req)
			if w.Code != http.StatusOK {
				t.Fatalf("collect draft HTTP%d %s", w.Code, w.Body.String())
			}
			if json.Unmarshal(w.Body.Bytes(), &submitted) != nil {
				t.Fatal("collect response")
			}
			doc, e = declarations.Get(f.ctx, submitted.Data.DeclarationID, 1)
			if e != nil {
				t.Fatal(e)
			}
			current, e = revisions.CurrentRevision(f.ctx)
			if e != nil {
				t.Fatal(e)
			}
			finger, e = observations.CurrentFingerprint(f.ctx, doc.DeclarationID, doc.Operations)
			if e != nil {
				t.Fatal(e)
			}
			made, e = plans.Create(f.ctx, planengine.AuthorScope{PrincipalID: "human-a", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "role-integration"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: doc.DeclarationID, DeclarationRevision: 1, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, ObservationFingerprint: finger, IdempotencyKey: "role-collect-plan", Extensions: doc.Extensions})
			if e != nil {
				t.Fatal("collect plan", e)
			}
			p = made.Plan
			card, e = ack.Request(f.ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: "role-collect-nonce"}, p.PlanID)
			if e != nil {
				t.Fatal(e)
			}
			expires, _ = time.Parse(time.RFC3339, card.Request.ExpiresAt)
			approved, e = ack.Decide(f.ctx, acknowledgement.Candidate{Human: slackHuman, AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove, PlanID: p.PlanID, PlanDigest: p.PlanDigest, TargetDigest: card.Request.TargetDigest, ReasonDigest: card.Request.ReasonDigest, Nonce: card.Nonce, StateRevision: card.Request.StateRevision, RecoveryEpoch: card.Request.RecoveryEpoch, ExpiresAt: expires, DecidedAt: at})
			if e != nil {
				t.Fatal(e)
			}
			decision.PlanDigest = p.PlanDigest
			decision.DecisionID = "collect-decision"
			applied, e = engine.Submit(f.ctx, runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, IdempotencyKey: "run-role-collect", Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: audit.Attribution{AuthenticatedPrincipalID: human.ID, AuthenticatedPrincipalMethod: human.Method, ResponsibleHumanPrincipalID: &human.ID}})
			if e != nil || applied.Status != "succeeded" || targetOS.calls != 2 || targetOS.result.Changed || !targetOS.result.EffectObserved {
				t.Fatalf("collect failed run=%+v err=%v calls=%d", applied, e, targetOS.calls)
			}
			if _, e = readiness.snapshot(f.ctx, in.HostID, true); e == nil {
				t.Fatal("role collect substituted for baseline recollection")
			}
			changed := in
			changed.Resources.TasksMax++
			changed.RoleBindingDigest = linuxrole.RoleBindingDigest(changed)
			changed.RenderedPolicyDigest = linuxrole.PolicyDigest(changed)
			if _, e = readiness.PrepareRole(f.ctx, "debian.role.apply", changed); e == nil {
				t.Fatal("changed role reused invalidated prior baseline")
			}

		})
	}
}

//go:embed testdata/linux-role-input.json
var roleTestInputJSON []byte

func roleTestInput(t *testing.T, access generated.DebianAccessInput) generated.LinuxRoleInput {
	t.Helper()
	raw := roleTestInputJSON
	var in generated.LinuxRoleInput
	if json.Unmarshal(raw, &in) != nil {
		t.Fatal("role fixture")
	}
	in.HostID = access.HostID
	in.HostIdentityDigest = access.HostIdentityDigest
	in.ProfileID = access.ProfileID
	in.ProfileLock = access.ProfileLock
	in.ProfileLockDigest = access.ProfileLockDigest
	in.AutomationUID = access.AutomationUID
	in.Accounts[0].UID = access.AutomationUID
	in.Accounts[0].GID = access.AutomationUID
	for i := range in.Directories {
		in.Directories[i].UID = access.AutomationUID
		in.Directories[i].GID = access.AutomationUID
	}
	in.NetworkAccess = &access
	in.ControlIDs = []string{"linux.role-identity-paths"}
	in.RoleBindingDigest = linuxrole.RoleBindingDigest(in)
	in.RenderedPolicyDigest = linuxrole.PolicyDigest(in)
	return in
}

type roleTestReadiness struct {
	repo  *store.GateRepository
	clock func() time.Time
}

func (r roleTestReadiness) snapshot(ctx context.Context, id string, require bool) (store.HostAdmissionSnapshot, error) {
	s, e := r.repo.CheckHostAdmission(ctx, id, "role-install", r.clock())
	if e != nil || !require {
		return s, e
	}
	p, e := r.repo.GetAppliedProfileScope(ctx)
	if e != nil {
		return s, e
	}
	v, e := gate.EvaluateHostAdmission(ctx, s, gate.ResolvedScope{ProfileID: p.ProfileID, ProfileVersion: p.ProfileVersion, PolicyID: p.PolicyID, PolicyVersion: p.PolicyVersion, Capabilities: p.Capabilities, StateRevision: p.StateRevision, RecoveryEpoch: p.RecoveryEpoch}, "host.hardening-baseline", r.clock())
	if e != nil {
		return s, e
	}
	if v.Outcome != "passed" {
		return s, errors.New(v.ReasonCode)
	}
	return s, nil
}
func (r roleTestReadiness) PrepareRole(ctx context.Context, action string, in generated.LinuxRoleInput) (generated.LinuxRoleInput, error) {
	s, e := r.snapshot(ctx, in.HostID, action != "debian.role.collect")
	if e != nil {
		return in, e
	}
	d := store.HostAdmissionSnapshotDigest(s)
	if in.BaselineSnapshotDigest != "" && in.BaselineSnapshotDigest != d {
		return in, errors.New("stale")
	}
	if in.HostIdentityDigest != s.IdentityDigest || in.ProfileLockDigest != s.ProfileLockDigest || in.CurrentRoleBindingDigest != s.RoleBindingDigest {
		return in, errors.New("identity")
	}
	in.BaselineSnapshotDigest = d
	in.RenderedPolicyDigest = linuxrole.PolicyDigest(in)
	return in, nil
}
func (r roleTestReadiness) VerifyRoleBaseline(ctx context.Context, p generated.Plan) (store.HostAdmissionSnapshot, error) {
	return r.snapshot(ctx, p.HostRoleScope.SubjectHostID, p.HostAction.ActionID != "debian.role.collect")
}

type roleTestPlans struct{ *planengine.Service }

func (r roleTestPlans) Get(ctx context.Context, id string) (generated.Plan, error) {
	p, e := r.Service.Get(ctx, id)
	return p.Plan, e
}

type roleTestCredential struct{}

func (roleTestCredential) Resolve(context.Context, credentialref.StepBinding) (*credentialref.Value, error) {
	return credentialref.NewValue([]byte("synthetic-os-credential"))
}
func (roleTestCredential) GetAppliedProfileScope(context.Context) (store.GateAppliedProfile, error) {
	return store.GateAppliedProfile{ProfileID: "synthetic-role-profile", Capabilities: []string{"synthetic-role-ssh"}, StateRevision: 1}, nil
}

type roleTestSecretGate struct{ hosts *store.HostActionRepository }

func (g roleTestSecretGate) VerifySecretStep(ctx context.Context, p generated.Plan, op generated.PlanOperation) error {
	if p.HostAction == nil || p.HostAction.HostID != op.TargetID {
		return errors.New("target")
	}
	r := p.HostAction
	return g.hosts.VerifyHostActionConsole(ctx, r.HostID, generated.HostActionCredentialConfirmation{Method: r.ConsoleConfirmation.Method, TargetDigest: r.TargetDigest, HostIdentityDigest: r.ConsoleConfirmation.HostIdentityDigest, TargetRevision: r.TargetRevision}, p.Binding.RecoveryEpoch)
}

type roleTestOS struct {
	authority *store.Store
	hosts     *store.HostActionRepository
	clock     func() time.Time
	calls     int
	binding   adapter.ExactExecutionBinding
	result    generated.HostActionResult
}

func (o *roleTestOS) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	return adapter.Effect{}, errors.New("unbound")
}
func (o *roleTestOS) ExecuteBoundWithCredentials(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, values []*credentialref.Value) (adapter.Effect, error) {
	current, e := o.hosts.CurrentExecution(ctx, op, b)
	if e != nil {
		return adapter.Effect{}, e
	}
	if len(values) != 1 {
		return adapter.Effect{}, errors.New("credential")
	}
	in, e := linuxrole.DecodeInput([]byte(current.Draft.Request.ActionInput))
	if e != nil {
		return adapter.Effect{}, e
	}
	o.calls++
	o.binding = b
	d := hostaction.Digest(b)
	m := generated.AccessMeasurement{Schema: generated.SchemaIDAccessMeasurement, SchemaVersion: "1.0.0", ControlID: in.ControlIDs[0], Kind: "role", Status: "passed", SubjectHostID: in.HostID, SubjectIdentityDigest: in.HostIdentityDigest, ProfileLockDigest: in.ProfileLockDigest, ProducerID: "linux-role", ProducerVersion: "1.0.0", BundleDigest: d, ObservedAt: o.clock().Format(time.RFC3339), ConfigurationDigest: current.Draft.Request.ActionInputDigest, PositiveProbeDigest: d, NegativeProbeDigest: d, Reason: "synthetic-os", Role: &generated.RoleObservation{Schema: generated.SchemaIDRoleObservation, SchemaVersion: "1.0.0", RoleID: in.RoleID, RoleBindingDigest: in.RoleBindingDigest, FactsDigest: d, Verification: "effective-probe"}}
	m.MeasurementDigest = hostaction.MeasurementDigest(m)
	changed := current.Draft.Request.ActionID == "debian.role.apply"
	o.result = generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: d, Status: "succeeded", Changed: changed, EffectObserved: true, Reason: "synthetic-os", ControlMeasurements: []generated.AccessMeasurement{m}}
	o.result.ResultDigest = hostaction.ResultDigest(o.result)
	return adapter.Effect{Status: "succeeded", Changed: changed, EffectObserved: true, ResultDigest: o.result.ResultDigest}, nil
}
func (o *roleTestOS) Verify(ctx context.Context, op adapter.Operation, e adapter.Effect) (adapter.Verification, error) {
	a, err := o.authority.HostAccessRunAttribution(ctx, o.binding.RunID)
	if err != nil {
		return adapter.Verification{}, err
	}
	err = o.authority.RecordHostControlResults(ctx, store.HostControlResultsRequest{Operation: op, Binding: o.binding, Effect: e, Result: o.result, Attribution: a})
	return adapter.Verification{Verified: err == nil, Digest: e.ResultDigest}, err
}
