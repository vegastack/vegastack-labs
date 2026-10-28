//go:build linux

package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
	"github.com/vegastack/vegastack-labs/internal/adapter/serviceruntime"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"github.com/vegastack/vegastack-labs/internal/store"
	"golang.org/x/crypto/ssh"
)

// This fixture uses the actual SQLite/controller/SSH/private stream/default
// typed Coolify consumer. The peer models held PID1, not Docker qualification.
// Independent-verifier prerequisites are intentionally incomplete: the real
// composition must deny terminal success after the observed provider mutation.
func TestCIExternalDeploymentConsumedPrivateStream(t *testing.T) {
	for _, fault := range []string{"consumed", "resolve-revoked", "request-revoked", "controller-lease-revoked", "deployment-lease-revoked"} {
		t.Run(fault, func(t *testing.T) {
			wire := &ciJobWireFixture{fault: fault, deployment: true}
			hostActionAcceptance(t, "success", hostActionAcceptanceHooks{EnrollmentOnly: true, Peer: func(t *testing.T, k ssh.Signer, s ActionSigner, w *atomic.Int32, d string) int {
				return hostActionAcceptancePeerDispatcher(t, k, s, w, d, wire)
			}, Enrollment: func(t *testing.T, f hostActionEnrollmentFixture) adapter.CredentialResolver {
				testCIJobController(t, f, wire)
				return nil
			}})
		})
	}
}

type ciExternalWorkflowFixture struct {
	t             *testing.T
	host          hostActionEnrollmentFixture
	policy        store.CIExternalDeploymentPolicy
	service       servicecatalog.Policy
	profile       serverconfig.Profile
	authority     *store.Store
	jobs          *store.CIJobRepository
	controlValue  *ciExternalDeploymentControl
	writes        atomic.Int32
	reads         atomic.Int32
	resolutions   atomic.Int32
	retained      []byte
	child         generated.Plan
	childRun      generated.Run
	replayChecked atomic.Bool
	fault         string
}

func newCIExternalWorkflowFixture(t *testing.T, f hostActionEnrollmentFixture, b generated.CiJobExecutionBinding) *ciExternalWorkflowFixture {
	x := &ciExternalWorkflowFixture{t: t, host: f}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer deployment-private-synthetic" {
			t.Error("wrong deployment credential")
		}
		x.reads.Add(1)
		if x.fault == "request-revoked" && r.Method == "GET" {
			_, e := f.DB.Exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='external-executor'`)
			if e != nil {
				t.Error(e)
			}
		}
		if !x.replayChecked.Swap(true) && x.fault == "consumed" {
			parent, lease := x.currentPair()
			if e := x.jobs.ConsumeDeploymentHandoff(f.Context, parent, x.child, lease); store.Code(e) != generated.ErrorCodeStateConflict {
				t.Errorf("handoff replay: %v", e)
			}
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/team":
			fmt.Fprint(w, `{"id":1}`)
		case "GET /api/v1/projects/project-one":
			fmt.Fprint(w, `{"id":2,"uuid":"project-one"}`)
		case "GET /api/v1/projects/project-one/production":
			fmt.Fprint(w, `{"id":3,"project_id":2,"name":"production"}`)
		case "GET /api/v1/applications/app-one":
			fmt.Fprint(w, `{"uuid":"app-one","environment_id":3,"destination_id":4,"destination_type":"App\\Models\\StandaloneDocker","build_pack":"dockerimage","additional_servers_count":0,"additional_networks_count":0}`)
		case "GET /api/v1/applications/app-one/destinations":
			fmt.Fprint(w, `[{"uuid":"destination-one","server_uuid":"server-one","server_id":5,"is_primary":true}]`)
		case "GET /api/v1/servers/server-one":
			fmt.Fprint(w, `{"id":5,"uuid":"server-one"}`)
		case "PATCH /api/v1/applications/app-one":
			var got map[string]string
			if json.NewDecoder(r.Body).Decode(&got) != nil || len(got) != 2 || got["docker_registry_image_name"] != x.policy.Artifact.Repository || got["docker_registry_image_tag"] != "sha256-"+strings.Repeat("a", 64) {
				t.Error("changed exact image")
			}
			x.writes.Add(1)
			fmt.Fprint(w, `{"uuid":"app-one"}`)
		case "POST /api/v1/deploy":
			x.writes.Add(1)
			fmt.Fprint(w, `{"deployments":[{"resource_uuid":"app-one","deployment_uuid":"deployment-one"}]}`)
		case "GET /api/v1/deployments/applications/app-one":
			fmt.Fprint(w, `{"deployments":[{"deployment_uuid":"deployment-one"}],"count":1}`)
		case "GET /api/v1/deployments/deployment-one":
			fmt.Fprint(w, `{"deployment_uuid":"deployment-one","status":"finished","server_id":5,"destination_id":"4","logs":"deployment-private-synthetic"}`)
		default:
			t.Errorf("unexpected Coolify route %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	// Explicit synthetic TLS trust is process-local fixture input. Production
	// continues to use strict default trust and public HTTPS network qualification.
	cert, e := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	certPath := filepath.Join(f.Directory, "fixture-ca.pem")
	if e = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("SSL_CERT_FILE", certPath)
	t.Setenv("SSL_CERT_DIR", filepath.Join(f.Directory, "no-cert-directory"))
	definition := generated.ServiceDefinition{Schema: generated.SchemaIDServiceDefinition, SchemaVersion: "1.0.0", ServiceID: "service-a", EnvironmentID: "production", OwnerID: "operator-a", HostID: "synthetic-host", HostIdentityDigest: f.DestinationIdentity, BindingID: "service-binding", BindingDigest: hostaction.Digest("service-binding")}
	x.service = servicecatalog.Policy{Definition: definition, ResourceKeyDigest: hostaction.Digest("service-resource")}
	x.policy = store.CIExternalDeploymentPolicy{Binding: generated.CiExternalDeploymentBinding{Schema: generated.SchemaIDCiExternalDeploymentBinding, SchemaVersion: "1.0.0", BindingID: "external-one", ExecutionBindingID: b.BindingID, ServiceID: "service-a", ArtifactID: "image-one", ExecutorID: b.AutomationPrincipalID, MaterialVersion: "version-a", ResolverID: "fixture-deployment"}, Definition: definition, Artifact: generated.ServiceDeploymentArtifact{Schema: generated.SchemaIDServiceDeploymentArtifact, SchemaVersion: "1.0.0", ArtifactID: "image-one", Repository: "registry.example/app", Digest: "sha256:" + strings.Repeat("a", 64), ManifestSHA: hostaction.Digest("manifest"), BundleSHA: hostaction.Digest("bundle"), PolicySHA: hostaction.Digest("policy")}, ConfigurationDigest: hostaction.Digest("configuration"), ReferenceID: "deployment-key", ResolverID: "fixture-deployment"}
	x.profile = serverconfig.Profile{CIExternalDeployments: []generated.CiExternalDeploymentBinding{x.policy.Binding}, ServiceBindings: []generated.ServiceProviderBinding{{ServiceID: "service-a", Coolify: &generated.CoolifyServiceBinding{Origin: server.URL + "/api/v1", TeamID: 1, ProjectID: 2, ProjectUUID: "project-one", EnvironmentID: 3, Environment: "production", ApplicationUUID: "app-one", DestinationID: 4, DestinationType: `App\Models\StandaloneDocker`}}}, ServiceDeploymentBindings: []generated.ServiceDeploymentProviderBinding{{Binding: generated.ServiceDeploymentBinding{ServiceID: "service-a"}, DestinationUUID: "destination-one", ServerUUID: "server-one", ServerID: 5}}}
	return x
}
func (x *ciExternalWorkflowFixture) seed(t *testing.T, exec func(string, ...any), grant func(string, string, string, string, string, string, string)) {
	for _, g := range []struct{ id, principal, action, cap, kind, branch string }{{"external-read", "operator-a", "read", "service.read", "service", ""}, {"external-author", "operator-a", "author", "service.deploy.prepare", "service", ""}, {"external-human-execute", "operator-a", "execute", store.CIExternalDeploymentOperation, "execution-target", "human"}, {"external-ack", "operator-a", "acknowledge", "plan.acknowledge", "plan-target", "human"}, {"external-executor", "automation-a", "execute", store.CIExternalDeploymentOperation, "execution-target", "human"}} {
		grant(g.id, g.principal, g.action, g.cap, g.kind, "service-a", g.branch)
	}
	exec(`INSERT INTO gate_applied_profiles VALUES('external-profile','synthetic-profile','1.0.0','fixture-policy','1.0.0',?,1,0,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, []byte(`["synthetic-capability","credential.host-action.read","credential.hosting.mutate"]`), hostaction.Digest("profile"))
	exec(`INSERT INTO credential_reference_versions VALUES('deployment-version','deployment-key','hosting.coolify.deploy','hosting-deploy','service-a','fixture-deployment','version-a',?,'active',1,0,?,?,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, hostaction.Digest("secret-ciphertext"), time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), []byte(`["hosting.coolify.deploy"]`), hostaction.Digest("fixture"))
	record := generated.ServiceRecord{Schema: generated.SchemaIDServiceRecord, SchemaVersion: "1.0.0", Definition: x.service.Definition, Revision: 1, RegistrationStatus: "registered", HostAdmission: "not-verified", RegisteredAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)}
	raw, _ := json.Marshal(record)
	exec(`INSERT INTO service_catalog SELECT ?,?,?,?,?,plan_id,run_id FROM plan_runs LIMIT 1`, record.Definition.ServiceID, x.service.ResourceKeyDigest, raw, hostaction.Digest(record), hostaction.Digest("fixture-import"))
}
func (x *ciExternalWorkflowFixture) Resolve(ctx context.Context, b credentialref.StepBinding) (*credentialref.Value, error) {
	x.resolutions.Add(1)
	if b.ReferenceID != "deployment-key" || b.MaterialVersion != "version-a" || b.TargetID != "service-a" || b.ConsumerID != "hosting.coolify.deploy" {
		return nil, actionFailure()
	}
	if x.fault == "resolve-revoked" {
		if _, e := x.host.DB.Exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='external-executor'`); e != nil {
			return nil, e
		}
	}
	if x.fault == "controller-lease-revoked" || x.fault == "deployment-lease-revoked" {
		kind := "central"
		if x.fault == "deployment-lease-revoked" {
			kind = "external"
		}
		if _, e := x.host.DB.Exec(`UPDATE target_execution_leases SET status='expired' WHERE status='active' AND lease_kind=?`, kind); e != nil {
			return nil, e
		}
	}
	value, e := credentialref.NewValue([]byte("deployment-private-synthetic"))
	if e == nil {
		x.retained = value.Bytes()
	}
	return value, e
}
func (x *ciExternalWorkflowFixture) control(t *testing.T, s *store.Store, r *adapter.Registry, g *store.GateRepository, jobs *store.CIJobRepository, provider *githubci.Client, plans *planengine.Service, ack *acknowledgement.Service) *ciExternalDeploymentControl {
	x.authority = s
	x.jobs = jobs
	if e := r.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "fixture-deployment", ConsumerID: "hosting.coolify.deploy", ProfileID: "synthetic-profile", CapabilityID: "credential.hosting.mutate", Enabled: true}, x); e != nil {
		t.Fatal(e)
	}
	guard := &externalDeploymentAdmission{authority: s, registry: r, observer: provider, clock: time.Now, managed: jobs}
	base := &serviceCatalogComposition{repo: store.NewServiceRepository(s), creds: store.NewCredentialRepository(s), gates: g, store: s, registry: r, bindings: map[string]generated.ServiceProviderBinding{"service-a": x.profile.ServiceBindings[0]}}
	deployment := &serviceDeploymentComposition{base: base, repo: store.NewDeploymentRepository(s), bindings: map[string]generated.ServiceDeploymentProviderBinding{"service-a": x.profile.ServiceDeploymentBindings[0]}, owner: uint32(os.Geteuid()), runtime: serviceruntime.NewClient()}
	if e := r.Register(store.CIExternalDeploymentAdapter, newCIExternalDeploymentReceipt(deployment, jobs)); e != nil {
		t.Fatal(e)
	}
	ext, e := runengine.NewExternalExecutor(runengine.ExternalExecutorConfig{DeploymentAdmission: guard, Runs: store.NewRunRepository(s), Leases: store.NewExecutorLeaseRepository(s), Plans: plans, Admission: runengine.NewAdmissionGate(ack, time.Now), Adapters: r, Clock: time.Now})
	if e != nil {
		t.Fatal(e)
	}
	x.controlValue = &ciExternalDeploymentControl{authority: s, profile: x.profile, executors: ext, guard: guard, broker: ciDeploymentBroker{authority: s, jobs: jobs, registry: r, gates: g}}
	return x.controlValue
}
func (x *ciExternalWorkflowFixture) reserve(t *testing.T, ctx context.Context, plans *planengine.Service, ack *acknowledgement.Service, engine *runengine.Engine, parent generated.Plan) {
	companion, e := store.NewPlanRepository(x.authority).CICompanion(ctx, parent.PlanID)
	if e != nil {
		t.Fatal(e)
	}
	p := companion.Plan
	x.child = p
	human := identity.Principal{ID: "operator-a", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
	card, e := ack.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: "companion-ack"}, p.PlanID)
	if e != nil {
		t.Fatal(e)
	}
	approved := hostActionAcceptanceSlackApproval(t, ack, card)
	branch := "human"
	decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-external", PrincipalID: human.ID, Action: "execute", TargetID: "service-a", Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, RecoveryEpoch: p.Binding.RecoveryEpoch, PlanDigest: p.PlanDigest, DecidedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	x.childRun, e = engine.Submit(ctx, runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, RecoveryEpoch: p.Binding.RecoveryEpoch, IdempotencyKey: "external-run", Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: audit.Attribution{AuthenticatedPrincipalID: human.ID, AuthenticatedPrincipalMethod: identity.LocalOSPeerMethod, ResponsibleHumanPrincipalID: &human.ID}})
	if e != nil || x.childRun.Status != "running" {
		t.Fatalf("companion reservation: %v %+v", e, x.childRun)
	}
}
func (x *ciExternalWorkflowFixture) currentPair() (adapter.ExactExecutionBinding, generated.ExecutorLease) {
	var parent adapter.ExactExecutionBinding
	var raw []byte
	e := x.host.DB.QueryRow(`SELECT r.plan_id,r.plan_digest,j.run_id,j.step_id,j.lease_id,r.state_revision,r.recovery_epoch,l.maximum_expires_at FROM ci_job_executions j JOIN plan_runs r ON r.run_id=j.run_id JOIN target_execution_leases l ON l.lease_id=j.lease_id`).Scan(&parent.PlanID, &parent.PlanDigest, &parent.RunID, &parent.StepID, &parent.LeaseID, &parent.StateRevision, &parent.RecoveryEpoch, &parent.MaximumExpiresAt)
	if e != nil {
		x.t.Error(e)
	}
	var lease generated.ExecutorLease
	e = x.host.DB.QueryRow(`SELECT canonical_bytes FROM target_execution_leases WHERE run_id=?`, x.childRun.RunID).Scan(&raw)
	if e != nil {
		x.t.Error(e)
	}
	if e = json.Unmarshal(raw, &lease); e != nil {
		x.t.Error(e)
	}
	return parent, lease
}
func (x *ciExternalWorkflowFixture) assert(t *testing.T, ctx context.Context, s *store.Store, jobs *store.CIJobRepository, run generated.Run, p generated.Plan, wire *ciJobWireFixture) {
	if run.Status == "succeeded" || wire.allowed.Load() != 0 {
		t.Fatal("unqualified application reached terminal success", run.Status, wire.allowed.Load())
	}
	if x.resolutions.Load() != 1 {
		t.Fatalf("resolution count %d", x.resolutions.Load())
	}
	for _, b := range x.retained {
		if b != 0 {
			t.Fatal("broker retained plaintext")
		}
	}
	_, lease := x.currentPair()
	markers := 0
	for _, e := range lease.Extensions {
		if e.Name == "x-ci-deployment-handoff" {
			markers++
		}
	}
	if wire.fault == "consumed" {
		if x.writes.Load() != 2 || markers != 1 || !x.replayChecked.Load() {
			t.Fatalf("consumed path writes=%d markers=%d replay=%v reads=%d", x.writes.Load(), markers, x.replayChecked.Load(), x.reads.Load())
		}
	} else {
		if x.writes.Load() != 0 {
			t.Fatal("revoked provider mutation", x.writes.Load())
		}
		if wire.fault != "request-revoked" && markers != 0 {
			t.Fatal("revoked resolution consumed delivery")
		}
	}
	var cleanup string
	if e := x.host.DB.QueryRow(`SELECT cleanup_status FROM ci_job_executions WHERE run_id=?`, run.RunID).Scan(&cleanup); e != nil || cleanup == "verified" {
		t.Fatalf("uncertain cleanup reported verified: %q %v", cleanup, e)
	}
	var auditRaw []byte
	rows, e := x.host.DB.Query(`SELECT canonical_payload FROM audit_events`)
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	for rows.Next() {
		if e = rows.Scan(&auditRaw); e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(auditRaw), "deployment-private-synthetic") {
			t.Fatal("audit plaintext")
		}
	}
}
