//go:build linux

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/serviceruntime"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
)

func TestDeploymentReconcileDeniesBeforeProviderWithoutPriorAttempt(t *testing.T) {
	c, q := deploymentComposition(t, deploymentCompositionProfile())
	q.Action = "reconcile"
	// This composition has no durable prior attempt, no mutation credential, and
	// no provider transport. Reconciliation must reject without reaching any of
	// those dependencies rather than falling through the deployment callback.
	for _, actor := range []identity.Principal{{}, {ID: "human-a", Kind: identity.PrincipalHuman, Method: identity.LocalOSPeerMethod}} {
		out, e := c.Deploy(context.Background(), q, actor)
		if e == nil || out.Status != "partial" || out.ProviderReceiptID != "" {
			t.Fatal("unproven reconciliation accepted", out, e)
		}
	}
}

type reconciliationCredentials struct {
	reads  map[string]int
	writes int
	values []*credentialref.Value
}

func (r *reconciliationCredentials) Resolve(_ context.Context, b credentialref.StepBinding) (*credentialref.Value, error) {
	if b.ConsumerID != "hosting.coolify" && b.ConsumerID != "registry.harbor" && b.ConsumerID != "service.runtime" {
		r.writes++
		return nil, fmt.Errorf("unexpected mutation credential")
	}
	r.reads[b.ConsumerID]++
	v, e := credentialref.NewValue([]byte("fixture-service-secret"))
	r.values = append(r.values, v)
	return v, e
}

type reconciliationProvider struct {
	t              *testing.T
	image, created string
	application    map[string]any
	reads, writes  int
}

func (p *reconciliationProvider) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet {
		p.writes++
		return nil, fmt.Errorf("provider mutation forbidden")
	}
	p.reads++
	var body any
	switch r.URL.Path {
	case "/api/v1/teams/current":
		body = map[string]any{"id": 1}
	case "/api/v1/projects/project-a":
		body = map[string]any{"id": 2, "uuid": "project-a"}
	case "/api/v1/projects/project-a/production":
		body = map[string]any{"id": 3, "project_id": 2, "name": "production"}
	case "/api/v1/applications/app-a":
		body = p.application
	case "/api/v1/applications/app-a/destinations":
		body = []any{map[string]any{"uuid": "destination-a", "server_id": 5, "is_primary": true}}
	case "/api/v1/deployments/applications/app-a":
		body = map[string]any{"deployments": []any{map[string]any{"deployment_uuid": "receipt-a"}}}
	case "/api/v1/deployments/receipt-a":
		body = map[string]any{"deployment_uuid": "receipt-a", "status": "finished", "server_id": 5, "destination_id": 4, "created_at": p.created}
	default:
		if r.URL.Path != "/api/v2.0/projects/project/repositories/app/artifacts/"+p.image {
			p.t.Errorf("unexpected observation route %s", r.URL.Path)
			return nil, fmt.Errorf("unexpected observation route")
		}
		body = map[string]any{"digest": p.image, "project_id": 2, "repository_id": 3, "project_name": "project", "repository_name": "project/app", "manifest_media_type": "application/vnd.oci.image.manifest.v1+json", "scan_overview": map[string]any{"application/vnd.security.vulnerability.report; version=1.1": map[string]any{"scan_status": "Success", "complete_percent": 100, "summary": map[string]any{"total": 0}}}}
	}
	raw, e := json.Marshal(body)
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(raw))), Request: r}, e
}

type reconciliationNative struct {
	t               *testing.T
	fault           string
	calls, capacity int
}

func (n *reconciliationNative) ObserveCapacity(ctx context.Context, _ serviceruntime.Target, value *credentialref.Value, check serviceruntime.Check) (serviceruntime.CapacitySnapshot, error) {
	n.capacity++
	if len(value.Bytes()) == 0 {
		n.t.Fatal("missing native observation credential")
	}
	if e := check(ctx); e != nil {
		return serviceruntime.CapacitySnapshot{}, e
	}
	return serviceruntime.CapacitySnapshot{CPUQuotaPercent: 200, MemoryBytes: 536870912, StorageBytes: 2147483648, ObservedAt: time.Now().UTC().Format(time.RFC3339)}, nil
}

func (n *reconciliationNative) Observe(ctx context.Context, target serviceruntime.Target, selected serviceruntime.Selection, value *credentialref.Value, check serviceruntime.Check) (serviceruntime.Snapshot, error) {
	n.calls++
	if target.HostID != "synthetic-service-host" || selected.ApplicationUUID != "app-a" || selected.CPUQuotaPercent != 100 || selected.MemoryBytes != 268435456 || len(value.Bytes()) == 0 {
		n.t.Fatal("native selection escaped exact application/limits")
	}
	if e := check(ctx); e != nil {
		return serviceruntime.Snapshot{}, e
	}
	out := serviceruntime.Snapshot{ContainerID: strings.Repeat("a", 64), ImageID: strings.Repeat("b", 64), RepoDigest: selected.Repository + "@" + selected.Digest, Running: true, Health: "healthy", ObservedAt: time.Now().UTC().Format(time.RFC3339)}
	if n.fault == "unhealthy" {
		out.Health = "unhealthy"
	}
	if n.fault == "wrong-digest" {
		out.RepoDigest = selected.Repository + "@sha256:" + strings.Repeat("f", 64)
	}
	return out, nil
}

func TestDeploymentReconcileComposedReadOnlyNativeProof(t *testing.T) {
	for _, fault := range []string{"none", "unhealthy", "wrong-digest"} {
		t.Run(fault, func(t *testing.T) {
			x := newManualDeliveryCompositionFixture(t)
			f := x.f
			f.exec(`INSERT INTO effective_authorization_grants VALUES('reconcile-execute','operator-a','maintainer','execute','service.deploy','execution-target','service-a','human',1,'active','now','now')`)
			_, evidence := publicationCandidateFixture(t, "/unused-config")
			dir := t.TempDir()
			if e := os.Chmod(dir, 0700); e != nil {
				t.Fatal(e)
			}
			source := generated.ServiceDeploymentArtifactSource{Schema: generated.SchemaIDServiceDeploymentArtifactSource, SchemaVersion: "1.0.0", ArtifactID: "image-a", Repository: "registry.example/project/app", Digest: evidence.Expected.ImageDigest, ManifestPath: filepath.Join(dir, "manifest"), BundlePath: filepath.Join(dir, "bundle"), PolicyPath: filepath.Join(dir, "policy")}
			for path, raw := range map[string][]byte{source.ManifestPath: evidence.Manifest, source.BundlePath: evidence.ProvenanceBundle, source.PolicyPath: evidence.Policy} {
				if e := os.WriteFile(path, raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			artifact, e := deploymentArtifact(f.ctx, source, uint32(os.Geteuid()))
			if e != nil {
				t.Fatal("actual signed artifact", e)
			}
			x.db.Artifacts = []generated.ServiceDeploymentArtifactSource{source}
			x.db.ServerID = 5
			x.db.MutationReferenceID = "unselected-mutation"
			x.deployment.bindings[f.definition.ServiceID] = x.db
			x.deployment.owner = uint32(os.Geteuid())
			x.seedScope([]string{manualServiceCapability(f.source.bindings[f.definition.BindingID], x.db), "credential.service-runtime.read", "credential.hosting.read", "credential.registry.read"}, "labs-working-manual")
			f.credentialVersion("runtime-ref", "service.runtime", "runtime-observe", "one", "active", 1)
			resolver := &reconciliationCredentials{reads: map[string]int{}}
			registry := adapter.NewRegistry()
			for _, scope := range []adapter.CredentialCapabilityScope{{ResolverID: "fixture-service", ConsumerID: "hosting.coolify", ProfileID: "vegastack-labs", CapabilityID: "credential.hosting.read", Enabled: true}, {ResolverID: "fixture-service", ConsumerID: "registry.harbor", ProfileID: "vegastack-labs", CapabilityID: "credential.registry.read", Enabled: true}, {ResolverID: "fixture-service", ConsumerID: "service.runtime", ProfileID: "vegastack-labs", CapabilityID: "credential.service-runtime.read", Enabled: true}} {
				if e = registry.RegisterCredentialResolver(scope, resolver); e != nil {
					t.Fatal(e)
				}
			}
			f.source.registry = registry
			var seq int
			var name, dbpath string
			if e = f.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &dbpath); e != nil {
				t.Fatal(e)
			}
			if e = f.source.store.Close(); e != nil {
				t.Fatal(e)
			}
			authority, e := store.Open(f.ctx, store.Config{DatabasePath: dbpath, Mode: store.OpenExisting, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", ServiceImportPolicies: []servicecatalog.Policy{f.policy}, ServiceDeploymentPolicies: []servicecatalog.DeploymentPolicy{{Binding: x.db.Binding, Configuration: x.db.Configuration, Artifacts: []generated.ServiceDeploymentArtifact{artifact}}}})
			if e != nil {
				t.Fatal(e)
			}
			defer authority.Close()
			f.source.store = authority
			f.source.repo = store.NewServiceRepository(authority)
			f.source.creds = store.NewCredentialRepository(authority)
			f.source.gates = store.NewGateRepository(authority)
			x.deployment.repo = store.NewDeploymentRepository(authority)
			native := &reconciliationNative{t: t, fault: fault}
			x.deployment.runtime = native
			capacity, e := x.deployment.observeCapacity(f.ctx, f.definition, x.db)
			if e != nil {
				t.Fatal("fixture capacity", e)
			}
			q, e := x.deployment.repo.Prepare(f.ctx, generated.ServiceDeploymentDraftRequest{Schema: generated.SchemaIDServiceDeploymentDraftRequest, SchemaVersion: "1.0.0", ServiceID: f.definition.ServiceID, ArtifactID: "image-a", Action: "deploy", ExpectedStateRevision: 5, IdempotencyKey: "original-deploy", ReasonDigest: servicecatalog.Digest("reason")})
			if e != nil {
				t.Fatal(e)
			}
			q.Capacity = &capacity
			q.ArtifactProofDigest = servicecatalog.Digest(artifact)
			started := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
			finished := started.Add(2 * time.Minute)
			oldPlan := seedReconciliationPriorPlan(t, f, q, started, finished)
			q.Action = "reconcile"
			q.IdempotencyKey = "reconcile-selected"
			q.Recovery = &generated.ServiceDeploymentRecovery{Schema: generated.SchemaIDServiceDeploymentRecovery, SchemaVersion: "1.0.0", PriorPlanID: oldPlan.PlanID, PriorRunID: "reconcile-original-run", PriorStepID: "reconcile-original-step", PriorRequestDigest: servicecatalog.Digest(*oldPlan.ServiceDeployment), ProviderReceiptID: "receipt-a"}
			if e = servicecatalog.ValidateDeploymentRequest(q); e != nil {
				t.Fatal("fixture reconciliation request", e)
			}
			if _, e = x.deployment.repo.RecoveryAttempt(f.ctx, q); e != nil {
				t.Fatal("fixture prior attempt", e)
			}
			settings, e := deploymentImageSettings(*q.Configuration, true)
			if e != nil {
				t.Fatal(e)
			}
			settingsRaw, _ := json.Marshal(settings)
			app := map[string]any{}
			json.Unmarshal(settingsRaw, &app)
			for k, v := range map[string]any{"uuid": "app-a", "environment_id": 3, "destination_id": 4, "destination_type": `App\Models\StandaloneDocker`, "docker_registry_image_name": q.Artifact.Repository, "docker_registry_image_tag": "sha256-" + strings.TrimPrefix(q.Artifact.Digest, "sha256:"), "status": "running:healthy"} {
				app[k] = v
			}
			provider := &reconciliationProvider{t: t, image: q.Artifact.Digest, created: started.Add(time.Minute).Format(time.RFC3339), application: app}
			f.source.coolifyTransport = provider
			f.source.harborTransport = provider
			out, e := x.deployment.Deploy(f.ctx, q, f.actor)
			if fault == "none" {
				if e != nil || out.Status != "succeeded" || !out.Running || !out.Healthy || out.RunningDigest != q.Artifact.Digest || out.ProviderReceiptID != "receipt-a" {
					t.Fatal("composed reconciliation", out, e)
				}
			} else if e == nil || out.Status == "succeeded" {
				t.Fatal("invalid native proof accepted", out, e)
			}
			if native.calls != 1 || native.capacity != 2 || provider.reads == 0 || provider.writes != 0 || resolver.writes != 0 {
				t.Fatal("observation path or mutation boundary", native.calls, native.capacity, provider.reads, provider.writes, resolver.writes)
			}
			for _, consumer := range []string{"hosting.coolify", "registry.harbor", "service.runtime"} {
				if resolver.reads[consumer] == 0 {
					t.Fatal("selected reader never borrowed", consumer)
				}
			}
			for _, v := range resolver.values {
				if len(v.Bytes()) != 0 {
					t.Fatal("observation credential remained open")
				}
			}
			var status, effect string
			if e = f.db.QueryRow(`SELECT r.status,s.effect_state FROM plan_runs r JOIN plan_run_steps s ON s.run_id=r.run_id WHERE r.run_id='reconcile-original-run'`).Scan(&status, &effect); e != nil || status != "partial" || effect != "effect-unknown" {
				t.Fatal("original partial history rewritten", status, effect, e)
			}
			var records int
			if e = f.db.QueryRow(`SELECT COUNT(*) FROM service_deployments`).Scan(&records); e != nil || records != 0 {
				t.Fatal("composition appended an uncommitted result", records, e)
			}
		})
	}
}

// Only synthetic prior history is seeded here. Normal apply/verified record
// append is separately exercised by the real deployment repository tests.
func seedReconciliationPriorPlan(t *testing.T, f *serviceCatalogWorkflow, q generated.ServiceDeploymentRequest, started, finished time.Time) generated.Plan {
	t.Helper()
	hash := servicecatalog.Digest("synthetic-prior")
	readable := "readable\n"
	readableSum := sha256.Sum256([]byte(readable))
	p := generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", DeclarationID: "fixture-declaration", Binding: generated.PlanBinding{RecoveryEpoch: 0, PriorStateRevision: 4, StateRevision: 5, DeclarationRevision: 1, ObservationFingerprint: hash, TargetDigest: hash, ReasonDigest: hash, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0"}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: servicecatalog.DeploymentOperationID, OperationType: servicecatalog.DeploymentOperation, AdapterID: servicecatalog.DeploymentAdapterID, ExecutorID: "executor-central", TargetID: q.Definition.ServiceID, InputDigest: servicecatalog.Digest(q), ArtifactDigest: servicecatalog.Digest(q), Idempotent: false}}, Status: "planned", Risk: "production-like", AuthorizationBranch: "human", ExecutorMode: "central", CreatedAt: started.Format(time.RFC3339), ExpiresAt: started.Add(time.Duration(generated.PlanValiditySeconds) * time.Second).Format(time.RFC3339), ReadableDigest: "sha256:" + hex.EncodeToString(readableSum[:]), Extensions: []generated.ContractExtension{}, ServiceDeployment: &q}
	preimage, _ := json.Marshal(p)
	sum := sha256.Sum256(preimage)
	p.PlanDigest = "sha256:" + hex.EncodeToString(sum[:])
	p.PlanID = "plan-" + hex.EncodeToString(sum[:16])
	raw, _ := json.Marshal(p)
	f.exec(`INSERT INTO immutable_plans VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, p.PlanID, p.PlanDigest, p.DeclarationID, 1, 5, 0, hash, servicecatalog.Digest("prior-plan-key"), servicecatalog.Digest(q), raw, readable, p.ReadableDigest, p.CreatedAt, p.ExpiresAt)
	f.exec(`INSERT INTO plan_runs VALUES('reconcile-original-run',?,?,'decision',NULL,'1.0.0','central','executor-central',?,'partial',0,'required','incomplete',NULL,1,5,0,?,?,?,'now','now')`, p.PlanID, p.PlanDigest, hash, servicecatalog.Digest("prior-run-key"), servicecatalog.Digest(q), []byte(`{}`))
	f.exec(`INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,started_at,finished_at) VALUES('reconcile-original-step','reconcile-original-run',1,?,?,?,'executor-central',?,?,?,0,'partial','effect-unknown',?,?)`, servicecatalog.DeploymentOperationID, servicecatalog.DeploymentOperation, servicecatalog.DeploymentAdapterID, q.Definition.ServiceID, servicecatalog.Digest(q), servicecatalog.Digest(q), started.Format(time.RFC3339), finished.Format(time.RFC3339))
	f.exec(`INSERT INTO service_deployment_attempts VALUES(?,'reconcile-original-run','reconcile-original-step',?,?,0,'attempted')`, p.PlanID, servicecatalog.Digest(q), q.Definition.ServiceID)
	return p
}
