//go:build linux

package server

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/vegastack/vegastack-labs/internal/adapter/ociregistry"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// Actual SQLite/API/plan/human-ack/lease execution with real Sigstore signatures
// and an OCI Distribution TLS peer. No CI enrollment, job or GitHub observer exists.
type manualPublicationCredentialFixture struct{ publication atomic.Int32 }

func (r *manualPublicationCredentialFixture) Resolve(_ context.Context, b credentialref.StepBinding) (*credentialref.Value, error) {
	if b.ConsumerID == store.ManualPublicationAdapter && b.PurposeID == store.ManualPublicationPurpose {
		r.publication.Add(1)
		return credentialref.NewValue([]byte("publication-synthetic"))
	}

	return nil, actionFailure()
}
func TestManualPublicationApprovedController(t *testing.T) {
	for _, fault := range []string{"none", "credential-revoked", "lease-revoked", "unsigned", "registry-outage"} {
		t.Run(fault, func(t *testing.T) {
			hostActionAcceptance(t, "success", hostActionAcceptanceHooks{EnrollmentOnly: true, Enrollment: func(t *testing.T, f hostActionEnrollmentFixture) adapter.CredentialResolver {
				testManualPublicationController(t, f, fault)
				return nil
			}})
		})
	}
}
func testManualPublicationController(t *testing.T, f hostActionEnrollmentFixture, fault string) {
	t.Helper()
	ctx := f.Context
	exec := func(q string, a ...any) {
		t.Helper()
		if _, e := f.DB.Exec(q, a...); e != nil {
			t.Fatal(e)
		}
	}
	configPath := filepath.Join(f.Directory, "publication-config")
	candidatePath := filepath.Join(f.Directory, "publication-candidate")
	raw, evidence := manualPublicationFixture(t, configPath)
	policyPath := filepath.Join(f.Directory, "manual-policy")
	if e := os.WriteFile(policyPath, evidence.Policy, 0600); e != nil {
		t.Fatal(e)
	}
	if fault == "unsigned" {
		var v manualPublicationCandidate
		json.Unmarshal(raw, &v)
		v.Bundle = nil
		raw, _ = json.Marshal(v)
	}
	if e := os.WriteFile(configPath, []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(candidatePath, raw, 0600); e != nil {
		t.Fatal(e)
	}
	var leaseRun string
	revoked := false
	client, origin, writes := publicationRegistryFixture(t, func(r *http.Request) {
		if fault == "lease-revoked" && !revoked {
			revoked = true
			exec(`UPDATE target_execution_leases SET status='revoked' WHERE run_id=? AND status='active'`, leaseRun)
		}
	}, func(w http.ResponseWriter, r *http.Request) bool {
		if fault == "registry-outage" && r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/v2/team/app/manifests/") {
			w.WriteHeader(http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	binding := generated.ManualPublicationBinding{Schema: generated.SchemaIDManualPublicationBinding, SchemaVersion: "1.0.0", BindingID: "publish-binding", RegistryOrigin: origin, Repository: "team/app", ReferenceID: "publish-key", MaterialVersion: "version-a", CandidatePath: candidatePath, CandidateDigest: hostaction.BytesDigest(raw), TrustPolicyPath: policyPath, TrustPolicyDigest: hostaction.BytesDigest(evidence.Policy), ImageDigest: evidence.Expected.ImageDigest}
	if e := f.Authority.Close(); e != nil {
		t.Fatal(e)
	}
	authority, e := store.Open(ctx, store.Config{DatabasePath: filepath.Join(f.Directory, "control.db"), Mode: store.OpenExisting, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: time.Now, ManualPublicationBindings: []generated.ManualPublicationBinding{binding}})
	if e != nil {
		t.Fatal(e)
	}
	defer authority.Close()
	grant := func(id, action, cap, kind, branch string) {
		var b any
		if branch != "" {
			b = branch
		}
		exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?,?,?,1,'active','now','now')`, id, action, cap, kind, binding.BindingID, b)
	}
	grant("publication-author", "author", "artifact.publication.prepare", "manual-publication", "")
	grant("publication-read", "read", "artifact.publication.read", "manual-publication", "")
	grant("publication-execute", "execute", store.ManualPublicationOperation, "execution-target", "human")
	grant("publication-ack", "acknowledge", "plan.acknowledge", "plan-target", "human")
	exec(`INSERT INTO credential_reference_versions VALUES('publication-version','publish-key','oci-registry-manual','artifact.publish.manual','publish-binding','native-systemd','version-a',?,'active',1,0,?,?,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, hostaction.Digest("synthetic-publication-ciphertext"), time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), []byte(`["oci-registry-manual"]`), hostaction.Digest("synthetic"))
	exec(`INSERT INTO gate_applied_profiles VALUES('publication-profile','synthetic-profile','1.0.0','fixture-policy','1.0.0',?,1,0,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, []byte(`["credential.host-action.read","credential.registry.push"]`), hostaction.Digest("synthetic"))
	revisions := store.NewPlanRepository(authority)
	declarations, e := change.NewService(store.NewDeclarationRepository(authority), time.Now)
	if e != nil {
		t.Fatal(e)
	}
	observations, _ := planengine.NewStateObservationReader(revisions)
	plans, e := planengine.NewService(planengine.Config{Repository: revisions, Observations: observations, Clock: time.Now, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "control-plane", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if e != nil {
		t.Fatal(e)
	}
	effective := store.NewEffectiveAuthorizationRepository(authority)
	ack, e := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(authority), Plans: lifecycleAcceptancePlanReader{plans}, Authorizer: authorization.NewEvaluator(effective), Clock: time.Now})
	if e != nil {
		t.Fatal(e)
	}
	registry := adapter.NewRegistry()
	resolver := &manualPublicationCredentialFixture{}
	for _, scope := range []adapter.CredentialCapabilityScope{{ResolverID: "native-systemd", ConsumerID: store.ManualPublicationAdapter, ProfileID: "synthetic-profile", CapabilityID: "credential.registry.push", Enabled: true}} {
		if e = registry.RegisterCredentialResolver(scope, resolver); e != nil {
			t.Fatal(e)
		}
	}
	c := newManualPublicationComposition(authority, uint32(os.Geteuid()))
	c.newClient = func(string) (*ociregistry.Client, error) { return client, nil }
	if e = registry.Register(store.ManualPublicationAdapter, c); e != nil {
		t.Fatal(e)
	}
	application, e := api.NewApplication(api.Config{Authority: authority, Authorizer: store.NewReadAuthorizer(authority), Reads: store.NewReadRepository(authority), Results: f.Results})
	if e != nil {
		t.Fatal(e)
	}
	if e = api.RegisterDeclarationPlanOperations(application, api.DeclarationPlanConfig{Declarations: declarations, Plans: plans, Results: f.Results, Authorization: api.EffectiveAuthorizationConfig{Authorizer: authorization.NewEvaluator(effective), Recorder: effective, WorkflowOwners: authority, Clock: time.Now}}); e != nil {
		t.Fatal(e)
	}
	if e = api.RegisterManualPublicationOperations(application, api.ManualPublicationOperations{Jobs: store.NewManualPublicationRepository(authority), Declarations: declarations, Credentials: store.NewCredentialRepository(authority), Results: f.Results, Prepare: c.Prepare}); e != nil {
		t.Fatal(e)
	}
	current, e := revisions.CurrentRevision(ctx)
	if e != nil {
		t.Fatal(e)
	}
	input := generated.ManualPublicationDraftRequest{Schema: generated.SchemaIDManualPublicationDraftRequest, SchemaVersion: "1.0.0", BindingID: binding.BindingID, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: "publish-one", ReasonDigest: hostaction.Digest("publication-reason")}
	requestRaw, _ := json.Marshal(input)
	request := httptest.NewRequest("POST", "/api/v1/artifacts/publications/drafts", bytes.NewReader(requestRaw)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	application.ServeHTTP(response, request)
	if fault == "unsigned" {
		if response.Code == 200 || writes.Load() != 0 || resolver.publication.Load() != 0 {
			t.Fatal("unsigned publication admitted", response.Code)
		}
		return
	}
	if response.Code != 200 {
		t.Fatal("publication draft", response.Code, response.Body.String())
	}
	if bytes.Contains(response.Body.Bytes(), []byte("owner/repo")) || bytes.Contains(response.Body.Bytes(), []byte(candidatePath)) {
		t.Fatal("private publication policy exposed")
	}
	var envelope struct {
		Data generated.DeclarationRevision `json:"data"`
	}
	if e = json.Unmarshal(response.Body.Bytes(), &envelope); e != nil {
		t.Fatal(e)
	}
	d := envelope.Data
	prep, e := plans.Prepare(ctx, d.DeclarationID, d.Revision)
	if e != nil {
		t.Fatal(e)
	}
	created, e := plans.Create(ctx, planengine.AuthorScope{PrincipalID: "operator-a", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "publication-session"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: d.DeclarationID, DeclarationRevision: d.Revision, ExpectedStateRevision: prep.ExpectedStateRevision, RecoveryEpoch: prep.RecoveryEpoch, ObservationFingerprint: prep.ObservationFingerprint, IdempotencyKey: "publication-plan", Extensions: d.Extensions})
	if e != nil {
		t.Fatal(e)
	}
	p := created.Plan
	human := identity.Principal{ID: "operator-a", Kind: identity.PrincipalHuman, Method: identity.SlackSocketModeMethod}
	card, e := ack.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: "publication-ack-nonce"}, p.PlanID)
	if e != nil {
		t.Fatal(e)
	}
	approved := hostActionAcceptanceSlackApproval(t, ack, card)
	branch := "human"
	decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "publication-decision", PrincipalID: "operator-a", Action: "execute", TargetID: binding.BindingID, Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, PlanDigest: p.PlanDigest, DecidedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	if fault == "credential-revoked" {
		exec(`INSERT INTO credential_reference_versions SELECT 'publication-revoked',reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,fingerprint,'revoked',?,recovery_epoch,activated_at,verified_consumers_bytes,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,created_at FROM credential_reference_versions WHERE version_id='publication-version'`, p.Binding.StateRevision)
	}
	engine, e := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(authority), Plans: plans, Admission: runengine.NewAdmissionGate(ack, time.Now), Adapters: registry, SecretGate: manualPublicationGate{source: c}, CredentialStep: &runengine.CredentialStep{Bindings: store.NewCredentialRepository(authority), Resolvers: registry, Profiles: store.NewGateRepository(authority), Plans: plans, Clock: time.Now}, Clock: time.Now})
	if e != nil {
		t.Fatal(e)
	}
	// Derive the engine's deterministic run key only from its durable creation in
	// the registry callback; this is a test fault, never production selection.
	if fault == "lease-revoked" {
		c.newClient = func(string) (*ociregistry.Client, error) {
			if e = f.DB.QueryRow(`SELECT run_id FROM plan_runs WHERE plan_id=?`, p.PlanID).Scan(&leaseRun); e != nil {
				t.Fatal(e)
			}
			return client, nil
		}
	}
	run, submitErr := engine.Submit(ctx, runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, IdempotencyKey: "publication-run", Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: audit.Attribution{AuthenticatedPrincipalID: "operator-a", AuthenticatedPrincipalMethod: identity.LocalOSPeerMethod, ResponsibleHumanPrincipalID: &human.ID}})
	if fault == "none" {
		if submitErr != nil || run.Status != "succeeded" || writes.Load() != 3 || resolver.publication.Load() != 1 {
			t.Fatal("publication flow", run.Status, submitErr, writes.Load(), resolver.publication.Load())
		}
		var events int
		if e = f.DB.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type='artifact.publication.received' AND correlation_id=?`, run.RunID).Scan(&events); e != nil || events != 1 {
			t.Fatal("missing durable publication receipt", events, e)
		}
	} else {
		if run.Status == "succeeded" || (fault != "registry-outage" && writes.Load() != 0) {
			t.Fatal("denied publication escaped", fault, run, submitErr, writes.Load())
		}
		if fault == "registry-outage" {
			before := writes.Load()
			if before != 2 {
				t.Fatal("outage did not preserve attempted upload", before)
			}
			var attempted, uncertain int
			if e := f.DB.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type='artifact.publication.attempted' AND correlation_id=?`, run.RunID).Scan(&attempted); e != nil || attempted != 1 {
				t.Fatal("attempt lost", attempted, e)
			}
			if e := f.DB.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type LIKE 'artifact.publication.uncertain-%' AND correlation_id=?`, run.RunID).Scan(&uncertain); e != nil || uncertain != 1 {
				t.Fatal("uncertain result lost", uncertain, e)
			}
			again := runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, IdempotencyKey: "publication-run-again", Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: audit.Attribution{AuthenticatedPrincipalID: "operator-a", AuthenticatedPrincipalMethod: identity.LocalOSPeerMethod, ResponsibleHumanPrincipalID: &human.ID}}
			retry, retryErr := engine.Submit(ctx, again)
			if retryErr == nil && retry.Status == "succeeded" {
				t.Fatal("uncertain plan replayed")
			}
			if writes.Load() != before {
				t.Fatal("retry wrote to registry")
			}
		}
		if (fault == "credential-revoked") && resolver.publication.Load() != 0 {
			t.Fatal("publication credential delivered before completion/current authority")
		}
	}
}
