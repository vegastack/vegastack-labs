//go:build linux

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/serviceruntime"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/hostinglifecycle"
	"github.com/vegastack/vegastack-labs/internal/hostingplatform"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"github.com/vegastack/vegastack-labs/internal/store"
	"golang.org/x/crypto/ssh"
)

// Persisted records below are synthetic fixture seeds, never live gate evidence.
type manualDeliveryCompositionFixture struct {
	f             *serviceCatalogWorkflow
	hosting       *hostingLifecycleComposition
	deployment    *serviceDeploymentComposition
	conf          hostingConfiguration
	hp            generated.HostingLifecycleProfile
	db            generated.ServiceDeploymentProviderBinding
	target        generated.HostDiscoveryTarget
	targetDigest  string
	scopeRevision int64
}

func newManualDeliveryCompositionFixture(t *testing.T, mutate ...func(*hostingConfiguration)) *manualDeliveryCompositionFixture {
	t.Helper()
	sb := generated.ServiceProviderBinding{BindingID: "binding-a", ServiceID: "service-a", HostID: "synthetic-service-host", HostIdentityDigest: servicecatalog.Digest("synthetic-host-identity")}
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.NewSignerFromKey(key)
	if e != nil {
		t.Fatal(e)
	}
	target := generated.HostDiscoveryTarget{Schema: generated.SchemaIDHostDiscoveryTarget, SchemaVersion: "1.0.0", TargetID: "candidate-a", Revision: 1, Address: "127.0.0.1", Port: 2222, User: "inspect", HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), ProfileID: "synthetic-profile", CredentialReferenceID: "fixture-credential", MaterialVersion: "one", ExpectedOS: "debian", ExpectedVersion: "13", ExpectedArchitecture: "amd64"}
	draft := generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: "activate", IdempotencyKey: "fixture-target"}
	raw, _ := json.Marshal(draft)
	digest := hostdiscovery.Digest(draft)
	now := time.Now().UTC().Truncate(time.Second)
	observation := generated.HostObservation{Schema: generated.SchemaIDHostObservation, SchemaVersion: "1.0.0", ObservationID: "fixture-observation", TargetID: target.TargetID, TargetRevision: 1, TargetDigest: digest, Collector: hostdiscovery.CollectorID, CollectorVersion: "1.0.0", ObservedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(15 * time.Minute).Format(time.RFC3339), Status: "incomplete", Facts: []generated.HostDiscoveryFact{hostdiscovery.Fact("machine-id", "0123456789abcdef0123456789abcdef", "machine-id")}, Blockers: []string{"hardening-unverified"}}
	observation.ContentDigest = hostdiscovery.Digest(observation)
	raw, _ = json.Marshal(observation)

	conf := hostingConfiguration{Targets: []hostingTarget{{HostID: sb.HostID, IdentityDigest: sb.HostIdentityDigest, Role: "control"}}, Platform: &hostingplatform.Input{HostID: sb.HostID, HostIdentityDigest: sb.HostIdentityDigest, ComponentDirectory: "/data/coolify", ComposeDigest: hostaction.Digest("compose"), EnvironmentDigest: hostaction.Digest("environment"), PrivateAddress: "192.0.2.20", ManagementPort: 8000, ControllerDatabasePath: "/var/lib/vsk-labs/control.db", ControllerUnitDigest: hostaction.Digest("unit")}}
	if len(mutate) > 0 {
		mutate[0](&conf)
	}
	raw, _ = json.Marshal(conf)
	dir := t.TempDir()
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "hosting.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	hp := generated.HostingLifecycleProfile{Schema: generated.SchemaIDHostingLifecycleProfile, SchemaVersion: "1.0.0", BindingID: "hosting-binding", TargetID: "hosting-a", ConfigurationPath: path, ConfigurationDigest: hostaction.BytesDigest(raw), MutationReferenceID: "hosting-ref", PlatformReferenceID: "platform-ref"}
	config := generated.ServiceConfiguration{Schema: generated.SchemaIDServiceConfiguration, SchemaVersion: "1.0.0", EnvironmentClass: "development", CPUQuotaPercent: 100, MemoryBytes: 268435456, StorageBytes: 1073741824, Port: 8080, Exposure: "private", HealthPath: "/healthz", HealthExpectedStatus: 200, HealthIntervalSeconds: 10, HealthTimeoutSeconds: 2, HealthRetries: 3, DataClass: "stateless", Migration: "none", Rollback: "previous-artifact", SecretReferenceIDs: []string{}}
	artifact := generated.ServiceDeploymentArtifact{Schema: generated.SchemaIDServiceDeploymentArtifact, SchemaVersion: "1.0.0", ArtifactID: "image-a", Repository: "registry.example/project/app", Digest: hostaction.Digest("image"), ManifestSHA: hostaction.Digest("image"), BundleSHA: hostaction.Digest("bundle"), PolicySHA: hostaction.Digest("trust")}
	db := generated.ServiceDeploymentProviderBinding{Schema: generated.SchemaIDServiceDeploymentProviderBinding, SchemaVersion: "1.0.0", ServiceBindingID: sb.BindingID, Configuration: &config, Binding: generated.ServiceDeploymentBinding{Schema: generated.SchemaIDServiceDeploymentBinding, SchemaVersion: "1.0.0", ServiceID: sb.ServiceID, BindingID: "binding-a", ConfigurationDigest: servicecatalog.Digest(config), DataPolicy: "stateless"}, ExclusiveOwnership: true, RuntimeReferenceID: "runtime-ref", Artifacts: []generated.ServiceDeploymentArtifactSource{{ArtifactID: artifact.ArtifactID, Digest: artifact.Digest}}}
	f := newServiceCatalogWorkflowSeeded(t, func(binding generated.ServiceProviderBinding) serviceCatalogWorkflowSeed {
		sb = binding
		return serviceCatalogWorkflowSeed{Target: draft, Observation: observation, Profile: store.GateAppliedProfile{ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "labs-working-manual", PolicyVersion: "1.0.0", Capabilities: []string{manualHostingCapability(hp), manualServiceCapability(binding, db), "credential.service-runtime.read"}}}
	})
	f.register()
	f.exec(`INSERT INTO effective_authorization_grants VALUES('manual-host-read','operator-a','reader','read','host.read','host','synthetic-service-host',NULL,1,'active','now','now'),('manual-hosting-author','operator-a','infrastructure-admin','author','hosting.lifecycle.prepare','hosting','hosting-a',NULL,1,'active','now','now'),('manual-hosting-execute','operator-a','control-plane-admin','execute','hosting.lifecycle.apply','execution-target','hosting-a','human',1,'active','now','now'),('manual-deploy-author','operator-a','maintainer','author','service.deploy.prepare','service','service-a',NULL,1,'active','now','now')`)
	var seq int
	var name, dbpath string
	if e = f.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &dbpath); e != nil {
		t.Fatal(e)
	}
	if e = f.source.store.Close(); e != nil {
		t.Fatal(e)
	}
	authority, e := store.Open(f.ctx, store.Config{DatabasePath: dbpath, Mode: store.OpenExisting, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", ServiceImportPolicies: []servicecatalog.Policy{f.policy}, HostingLifecycleProfiles: []hostinglifecycle.Profile{{Binding: hp}}, ServiceDeploymentPolicies: []servicecatalog.DeploymentPolicy{{Binding: db.Binding, Configuration: &config, Artifacts: []generated.ServiceDeploymentArtifact{artifact}}}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { authority.Close() })
	f.source.store = authority
	f.source.repo = store.NewServiceRepository(authority)
	f.source.gates = store.NewGateRepository(authority)
	f.source.creds = store.NewCredentialRepository(authority)
	h := &hostingLifecycleComposition{repo: store.NewHostingLifecycleRepository(authority), store: authority, gates: f.source.gates, profiles: map[string]generated.HostingLifecycleProfile{hp.TargetID: hp}, owner: uint32(os.Geteuid())}
	d := &serviceDeploymentComposition{base: f.source, repo: store.NewDeploymentRepository(authority), bindings: map[string]generated.ServiceDeploymentProviderBinding{sb.ServiceID: db}}
	return &manualDeliveryCompositionFixture{f: f, hosting: h, deployment: d, conf: conf, hp: hp, db: db, target: target, targetDigest: digest, scopeRevision: 1}
}
func (x *manualDeliveryCompositionFixture) hostingRequest() generated.HostingLifecycleRequest {
	return generated.HostingLifecycleRequest{Schema: generated.SchemaIDHostingLifecycleRequest, SchemaVersion: "1.0.0", TargetID: x.hp.TargetID, BindingID: x.hp.BindingID, ConfigurationDigest: x.hp.ConfigurationDigest, ObservedDigest: hostaction.Digest("unobserved"), Action: "resources.apply", ExpectedStateRevision: 5, IdempotencyKey: "hosting-a", ReasonDigest: hostaction.Digest("reason")}
}
func TestManualDeliveryCompositionHostingAndPlatform(t *testing.T) {
	x := newManualDeliveryCompositionFixture(t)
	f := x.f
	q := x.hostingRequest()
	if e := x.hosting.checkTargets(f.ctx, q, x.conf); e != nil {
		t.Fatal("exact hosting", e)
	}
	input, _ := json.Marshal(x.conf.Platform)
	for _, action := range []string{hostingplatform.InstallAction, hostingplatform.VerifyAction} {
		r := generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", ActionID: action, ActionVersion: "1.0.0", ActionInput: string(input), ActionInputDigest: hostaction.BytesDigest(input), HostID: f.definition.HostID, TargetRevision: 1, TargetDigest: x.targetDigest, AutomationPrincipalID: "operator-a", CallerUID: 1002, CredentialReferenceID: x.hp.PlatformReferenceID, CredentialMaterialVersion: "one", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: x.targetDigest, HostIdentityDigest: f.definition.HostIdentityDigest}, ExpectedStateRevision: 5, IdempotencyKey: "platform-a"}
		if _, e := x.hosting.PrepareHostingPlatform(f.ctx, r); e != nil {
			t.Fatal(action, e)
		}
		r.ActionInput = strings.Replace(r.ActionInput, "/data/coolify", "/unbound", 1)
		r.ActionInputDigest = hostaction.BytesDigest([]byte(r.ActionInput))
		if _, e := x.hosting.PrepareHostingPlatform(f.ctx, r); e == nil {
			t.Fatal("changed platform input accepted")
		}
	}
	changed := x.conf
	changed.Targets = append(append([]hostingTarget{}, x.conf.Targets...), hostingTarget{HostID: "vsk-node-04", IdentityDigest: hostaction.Digest("excluded"), Role: "application"})
	if x.hosting.checkTargets(f.ctx, q, changed) == nil {
		t.Fatal("extra protected target accepted")
	}
	if _, e := (hostReplacementComposition{gates: f.source.gates, clock: time.Now}).roleAdmission(f.ctx, f.definition.HostID); e == nil {
		t.Fatal("manual mode qualified host")
	}
	x.seedScope(nil, "labs-working-manual")
	if x.hosting.checkTargets(f.ctx, q, x.conf) == nil {
		t.Fatal("revoked hosting scope accepted")
	}
}
func TestManualDeliveryCompositionDeploymentScope(t *testing.T) {
	x := newManualDeliveryCompositionFixture(t)
	f := x.f
	request, e := x.deployment.repo.Prepare(f.ctx, generated.ServiceDeploymentDraftRequest{Schema: generated.SchemaIDServiceDeploymentDraftRequest, SchemaVersion: "1.0.0", ServiceID: f.definition.ServiceID, ArtifactID: "image-a", Action: "deploy", ExpectedStateRevision: 5, IdempotencyKey: "deploy-a", ReasonDigest: hostaction.Digest("reason")})
	if e != nil {
		t.Fatal(e)
	}
	request.ArtifactProofDigest = servicecatalog.Digest(request.Artifact)
	if e = servicecatalog.ValidateDeploymentRequest(request); e != nil {
		t.Fatal("fixture deployment contract", e)
	}
	if _, e = x.deployment.authority(f.ctx, request, nil, true); e != nil {
		t.Fatal("exact deployment", e)
	}
	for _, mode := range []string{"public", "stateful", "artifact"} {
		b := x.db
		copy := *b.Configuration
		b.Configuration = &copy
		switch mode {
		case "public":
			copy.Exposure = "public"
		case "stateful":
			copy.DataClass = "stateful"
		case "artifact":
			b.Artifacts = append([]generated.ServiceDeploymentArtifactSource{}, b.Artifacts...)
			b.Artifacts[0].Digest = hostaction.Digest("other")
		}
		if mode != "artifact" {
			x.seedScope([]string{manualServiceCapability(f.source.bindings[f.definition.BindingID], b)}, "labs-working-manual")
		}
		if ok, e := x.deployment.manualAdmission(f.ctx, f.definition, b, 0); !ok || e == nil {
			t.Fatal("changed scope accepted", mode, ok, e)
		}
	}
	x.seedScope(nil, "strict-policy")
	if _, e = x.deployment.authority(f.ctx, request, nil, true); e == nil {
		t.Fatal("absence bypassed strict admission")
	}
}

// Exercise the production callback path, not a caller-set capacity result.
type manualCapacityObserver struct {
	onCheck func(context.Context) error
	revoke  func()
	calls   int
}

func (o *manualCapacityObserver) Observe(context.Context, serviceruntime.Target, serviceruntime.Selection, *credentialref.Value, serviceruntime.Check) (serviceruntime.Snapshot, error) {
	return serviceruntime.Snapshot{}, serviceruntime.ErrUnavailable
}
func (o *manualCapacityObserver) ObserveCapacity(ctx context.Context, _ serviceruntime.Target, _ *credentialref.Value, check serviceruntime.Check) (serviceruntime.CapacitySnapshot, error) {
	o.calls++
	if e := check(ctx); e != nil {
		return serviceruntime.CapacitySnapshot{}, e
	}
	o.revoke()
	if e := check(ctx); e != nil {
		return serviceruntime.CapacitySnapshot{}, e
	}
	return serviceruntime.CapacitySnapshot{CPUQuotaPercent: 200, MemoryBytes: 536870912, StorageBytes: 2147483648, ObservedAt: time.Now().UTC().Format(time.RFC3339)}, nil
}

type manualRuntimeResolver struct{}

func (manualRuntimeResolver) Resolve(_ context.Context, b credentialref.StepBinding) (*credentialref.Value, error) {
	return credentialref.NewValue([]byte("synthetic-runtime-key"))
}
func TestManualDeliveryCompositionCapacityRevocation(t *testing.T) {
	x := newManualDeliveryCompositionFixture(t)
	f := x.f
	f.credentialVersion("runtime-ref", "service.runtime", "runtime-observe", "one", "active", 1)
	if e := f.source.registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "fixture-service", ConsumerID: "service.runtime", ProfileID: "vegastack-labs", CapabilityID: "credential.service-runtime.read", Enabled: true}, manualRuntimeResolver{}); e != nil {
		t.Fatal(e)
	}
	observer := &manualCapacityObserver{revoke: func() { x.seedScope(nil, "labs-working-manual") }}
	x.deployment.runtime = observer
	if _, e := x.deployment.observeCapacity(f.ctx, f.definition, x.db); e == nil {
		t.Fatal("revoked callback accepted")
	}
	if observer.calls != 1 {
		t.Fatal("did not reach actual capacity callback", observer.calls)
	}
	var n int
	if e := f.db.QueryRow(`SELECT COUNT(*) FROM service_capacity_observations`).Scan(&n); e != nil || n != 0 {
		t.Fatal("revoked result persisted", n, e)
	}
}

func (x *manualDeliveryCompositionFixture) seedScope(caps []string, policy string) {
	x.scopeRevision++
	if caps == nil {
		caps = []string{}
	}
	raw, _ := json.Marshal(caps)
	x.f.exec(`INSERT INTO gate_applied_profiles SELECT ?,profile_id,profile_version,?,policy_version,?,?,recovery_epoch,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,applied_at FROM gate_applied_profiles WHERE binding_id='service-profile'`, fmt.Sprintf("manual-profile-%d", x.scopeRevision), policy, raw, x.scopeRevision)
}

// These fixtures intentionally bind an invalid protected platform declaration;
// preparation itself must reject it before a request can reach any host.
func TestManualDeliveryPlatformScopeMembership(t *testing.T) {
	for _, mode := range []string{"omitted", "identity", "role"} {
		t.Run(mode, func(t *testing.T) {
			x := newManualDeliveryCompositionFixture(t, func(c *hostingConfiguration) {
				switch mode {
				case "omitted":
					c.Platform.HostID = "distinct-control"
				case "identity":
					c.Platform.HostIdentityDigest = hostaction.Digest("different-control")
				case "role":
					c.Targets[0].Role = "application"
				}
			})
			in, _ := json.Marshal(x.conf.Platform)
			r := generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", ActionID: hostingplatform.InstallAction, ActionVersion: "1.0.0", ActionInput: string(in), ActionInputDigest: hostaction.BytesDigest(in), HostID: x.conf.Platform.HostID, TargetRevision: 1, TargetDigest: x.targetDigest, AutomationPrincipalID: "operator-a", CallerUID: 1002, CredentialReferenceID: x.hp.PlatformReferenceID, CredentialMaterialVersion: "one", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: x.targetDigest, HostIdentityDigest: x.conf.Platform.HostIdentityDigest}, ExpectedStateRevision: 5, IdempotencyKey: "platform-membership"}
			if _, e := x.hosting.PrepareHostingPlatform(x.f.ctx, r); e == nil {
				t.Fatal("platform outside complete target binding accepted", mode)
			}
		})
	}
}

type manualPlatformPreparerFunc func(context.Context, generated.HostActionRequest) (generated.HostActionRequest, error)

func (f manualPlatformPreparerFunc) PrepareHostingPlatform(ctx context.Context, r generated.HostActionRequest) (generated.HostActionRequest, error) {
	return f(ctx, r)
}

type manualPlatformTestDispatcher struct{ hostActionAcceptanceHandler }

func (d manualPlatformTestDispatcher) Lookup(id, version string) (hostaction.Handler, bool) {
	return d.hostActionAcceptanceHandler, hostingplatform.IsAction(id) && version == "1.0.0"
}

// Bind a real profile through declaration/plan, consumed Slack acknowledgement,
// active gate lease and CoreGateEffect -> GateRepository.ApplyProfileBinding.
func bindManualTestProfile(t *testing.T, f hostActionEnrollmentFixture, id string, scope store.GateAppliedProfile) {
	t.Helper()
	ctx := f.Context
	g := store.NewGateRepository(f.Authority)
	revisions := store.NewPlanRepository(f.Authority)
	current, e := revisions.CurrentRevision(ctx)
	if e != nil {
		t.Fatal(e)
	}
	humanID := "operator-a"
	attr := audit.Attribution{AuthenticatedPrincipalID: humanID, AuthenticatedPrincipalMethod: identity.LocalOSPeerMethod, ResponsibleHumanPrincipalID: &humanID}
	draft, e := g.PutProfileDraft(ctx, store.ProfileDraftRequest{BindingID: id, Scope: scope, Expected: current, KeyDigest: hostaction.Digest([]string{id, "draft-key"}), RequestDigest: hostaction.Digest([]string{id, "draft"}), Attribution: attr})
	if e != nil {
		t.Fatal("profile draft", e)
	}
	current, e = revisions.CurrentRevision(ctx)
	if e != nil {
		t.Fatal(e)
	}
	request, e := gate.BuildProfileChange(draft, current)
	if e != nil {
		t.Fatal(e)
	}
	// Exact synthetic setup grants only; approval is produced by the real service.
	for _, grant := range []struct{ action, cap, kind, target, branch string }{{"author", "declaration.author", "declaration", request.DeclarationID, ""}, {"author", "gate.profile.author", "profile", "profile-drafts", ""}, {"read", "gate.profile.read", "profile", "profile-drafts", ""}, {"acknowledge", "plan.acknowledge", "plan-target", scope.ProfileID, "human"}, {"execute", "gate.profile.bind", "execution-target", scope.ProfileID, "human"}} {
		var branch any
		if grant.branch != "" {
			branch = grant.branch
		}
		_, e = f.DB.Exec(`INSERT OR IGNORE INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?,?,?,1,'active','now','now')`, "manual-"+hostaction.Digest([]string{grant.action, grant.cap, grant.target})[7:35], grant.action, grant.cap, grant.kind, grant.target, branch)
		if e != nil {
			t.Fatal(e)
		}
	}
	revised, e := f.Declarations.Revise(ctx, change.AuthorScope{PrincipalID: humanID, PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "manual-policy-test"}, request)
	if e != nil {
		t.Fatal("profile declaration", e)
	}
	observations, e := planengine.NewStateObservationReader(revisions)
	if e != nil {
		t.Fatal(e)
	}
	plans, e := planengine.NewService(planengine.Config{Repository: revisions, Observations: observations, Clock: time.Now, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "control-plane", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if e != nil {
		t.Fatal(e)
	}
	current, e = revisions.CurrentRevision(ctx)
	if e != nil {
		t.Fatal(e)
	}
	fingerprint, e := observations.CurrentFingerprint(ctx, revised.Document.DeclarationID, revised.Document.Operations)
	if e != nil {
		t.Fatal(e)
	}
	created, e := plans.Create(ctx, planengine.AuthorScope{PrincipalID: humanID, PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "manual-policy-test"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: revised.Document.DeclarationID, DeclarationRevision: revised.Document.Revision, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, ObservationFingerprint: fingerprint, IdempotencyKey: id + "-plan", Extensions: []generated.ContractExtension{}})
	if e != nil {
		t.Fatal("profile plan", e)
	}
	ack, e := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(f.Authority), Plans: lifecycleAcceptancePlanReader{plans}, Authorizer: lifecycleAcceptanceAuthorizer{}, Clock: time.Now})
	if e != nil {
		t.Fatal(e)
	}
	human := identity.Principal{ID: humanID, Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
	card, e := ack.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: id + "-nonce"}, created.Plan.PlanID)
	if e != nil {
		t.Fatal(e)
	}
	approved := hostActionAcceptanceSlackApproval(t, ack, card)
	effect, e := runengine.NewCoreGateEffect(g, store.NewAcknowledgementRepository(f.Authority), "test", "test", time.Now)
	if e != nil {
		t.Fatal(e)
	}
	engine, e := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(f.Authority), Plans: plans, Admission: runengine.NewAdmissionGate(ack, time.Now), Adapters: adapter.NewRegistry(), Core: runengine.CoreRouter{Gate: effect}, Clock: time.Now})
	if e != nil {
		t.Fatal(e)
	}
	branch := "human"
	decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: id + "-decision", PrincipalID: humanID, Action: "execute", TargetID: authorization.ExecutionResourceIDs(created.Plan, created.Plan.Operations[0])[0], Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, PlanDigest: created.Plan.PlanDigest, DecidedAt: time.Now().UTC().Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	run, e := engine.Submit(ctx, runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: created.Plan.PlanID, PlanDigest: created.Plan.PlanDigest, IdempotencyKey: id + "-run", Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: attr})
	if e != nil || run.Status != "succeeded" {
		t.Fatal("real profile apply", run.Status, e)
	}
	applied, e := g.GetAppliedProfileScope(ctx)
	if e != nil || applied.PolicyID != scope.PolicyID || applied.StateRevision <= current.StateRevision {
		t.Fatal("profile binding not applied", applied, e)
	}
}

func TestManualDeliveryPlatformPreparedPolicyChangeDeniesExecution(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	digest := hostadoption.IdentityDigest("product-serial", "synthetic-serial")
	input := hostingplatform.Input{HostID: "synthetic-host", HostIdentityDigest: digest, ComponentDirectory: "/data/coolify", ComposeDigest: hostaction.Digest("compose"), EnvironmentDigest: hostaction.Digest("environment"), PrivateAddress: "192.0.2.20", ManagementPort: 8000, ControllerDatabasePath: "/var/lib/vsk-labs/control.db", ControllerUnitDigest: hostaction.Digest("unit")}
	conf := hostingConfiguration{Targets: []hostingTarget{{HostID: input.HostID, IdentityDigest: digest, Role: "control"}}, Platform: &input}
	raw, _ := json.Marshal(conf)
	path := filepath.Join(dir, "hosting.json")
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	hp := generated.HostingLifecycleProfile{Schema: generated.SchemaIDHostingLifecycleProfile, SchemaVersion: "1.0.0", TargetID: "hosting-a", BindingID: "hosting-bind", ConfigurationPath: path, ConfigurationDigest: hostaction.BytesDigest(raw), MutationReferenceID: "hosting-ref", PlatformReferenceID: "action-key"}
	var captured hostActionEnrollmentFixture
	var source *hostingLifecycleComposition
	reached := false
	scope := store.GateAppliedProfile{ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "labs-working-manual", PolicyVersion: "1.0.0", Capabilities: []string{manualHostingCapability(hp)}}
	hostActionAcceptance(t, "challenge-denial", hostActionAcceptanceHooks{
		ConfigureStore: func(c *store.Config) { c.HostingLifecycleProfiles = []hostinglifecycle.Profile{{Binding: hp}} },
		PlatformPreparer: manualPlatformPreparerFunc(func(ctx context.Context, r generated.HostActionRequest) (generated.HostActionRequest, error) {
			if source == nil {
				t.Fatal("platform source absent")
			}
			return source.PrepareHostingPlatform(ctx, r)
		}),
		ActionRequest: func(r generated.HostActionRequest) generated.HostActionRequest {
			r.ActionID = hostingplatform.InstallAction
			b, _ := json.Marshal(input)
			r.ActionInput = string(b)
			r.ActionInputDigest = hostaction.BytesDigest(b)
			return r
		},
		Peer: func(t *testing.T, key ssh.Signer, signer ActionSigner, writes *atomic.Int32, directory string) int {
			return hostActionAcceptancePeerDispatcher(t, key, signer, writes, directory, manualPlatformTestDispatcher{hostActionAcceptanceHandler{path: filepath.Join(directory, "action-result"), writes: writes}})
		},
		Enrollment: func(t *testing.T, f hostActionEnrollmentFixture) adapter.CredentialResolver {
			captured = f
			for _, v := range []struct{ action, cap, kind string }{{"author", "hosting.lifecycle.prepare", "hosting"}, {"execute", "hosting.lifecycle.apply", "execution-target"}} {
				if _, e := f.DB.Exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?,'hosting-a',?,1,'active','now','now')`, "platform-"+v.action, v.action, v.cap, v.kind, func() any {
					if v.action == "execute" {
						return "human"
					}
					return nil
				}()); e != nil {
					t.Fatal(e)
				}
			}
			bindManualTestProfile(t, f, "manual-initial", scope)
			// Enrollment hooks own their credential setup. This test uses the
			// same explicit synthetic active-key precondition as the default
			// helper; it does not exercise native credential enrollment.
			hash := hostdiscovery.Digest("fixture")
			if _, e := f.DB.Exec(`INSERT INTO credential_reference_versions VALUES('synthetic-version','action-key','host-action','host-action-ssh','synthetic-host','native-systemd','version-a',?,'active',1,0,?,?,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, hash, time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), []byte(`["host-action"]`), hash); e != nil {
				t.Fatal("synthetic host-action credential setup", e)
			}
			if _, e := store.NewCredentialRepository(f.Authority).GetActiveVersion(f.Context, "action-key", 0); e != nil {
				t.Fatal("synthetic key not active before platform draft", e)
			}
			source = &hostingLifecycleComposition{repo: store.NewHostingLifecycleRepository(f.Authority), store: f.Authority, gates: store.NewGateRepository(f.Authority), profiles: map[string]generated.HostingLifecycleProfile{hp.TargetID: hp}, owner: uint32(os.Geteuid())}
			return hostActionAcceptanceCredential{key: f.Key}
		},
		Challenge: func(t *testing.T, _ *sql.DB, _ *time.Time, authority *HostActionAuthority, envelope generated.HostActionEnvelope, challenge generated.HostActionChallenge) (generated.HostActionAuthorization, error) {
			reached = true
			if envelope.Bundle.ActionID != hostingplatform.InstallAction {
				t.Fatal("not a prepared platform action")
			}
			if _, e := authority.Authorize(captured.Context, envelope, challenge); e != nil {
				t.Fatal("actual consumed-ack/active-lease boundary unreachable before policy change", e)
			}
			changed := scope
			changed.Capabilities = []string{}
			bindManualTestProfile(t, captured, "manual-revoked", changed)
			if _, e := authority.Authorize(captured.Context, envelope, challenge); e == nil {
				t.Fatal("old platform challenge authorized after actual profile apply")
			}
			return generated.HostActionAuthorization{}, actionFailure()
		},
	})
	if !reached {
		t.Fatal("platform action did not reach actual fresh challenge")
	}
}
