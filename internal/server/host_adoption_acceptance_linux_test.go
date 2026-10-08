//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
	"golang.org/x/crypto/ssh"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real temporary SQLite, API, declaration/plan, synthetic Slack approval and run engine.
// No collector, credential resolver, host transport, or external adapter is registered.
func TestHostAdoptionAcceptanceHasNoExternalAction(t *testing.T) {
	hostAdoptionAcceptance(t, "success")
}
func TestHostAdoptionAcceptanceDenials(t *testing.T) {
	for _, mode := range []string{"prepare-denied", "missing-ack", "wrong-ack"} {
		t.Run(mode, func(t *testing.T) { hostAdoptionAcceptance(t, mode) })
	}
}
func hostAdoptionAcceptance(t *testing.T, mode string) {
	principal := identity.Principal{ID: "operator-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	ctx := identity.WithVerifiedPrincipal(context.Background(), principal)
	captureStart := time.Now().UTC().Truncate(time.Second)
	fixtureNow := captureStart
	clock := func() time.Time { return fixtureNow }
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.db")
	authority, err := store.Open(ctx, store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO effective_authorization_principals VALUES('operator-a','human','active',1,'now','now')`)
	grant := func(capability, kind, id, action string) {
		t.Helper()
		exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?, ?,NULL,1,'active','now','now')`, "grant-"+hostdiscovery.Digest([]string{capability, id})[7:25], action, capability, kind, id)
	}
	for _, c := range []string{"host.discovery.collect", "host.discovery.read"} {
		grant(c, "host-discovery-target", "candidate-a", "read")
	}
	grant("host.adoption.prepare", "host-discovery-target", "candidate-a", "author")
	grant("host.read", "host", "synthetic-host", "read")
	exec(`INSERT INTO read_principals VALUES('operator-a','active',1,'now','now')`)
	exec(`INSERT INTO read_grants VALUES('operator-a','host.discovery.read','host-discovery-target','candidate-a',1,'active','now','now')`)
	repo := store.NewHostAdoptionRepository(authority)
	revisions := store.NewPlanRepository(authority)
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	observations, err := planengine.NewStateObservationReader(revisions)
	if err != nil {
		t.Fatal(err)
	}
	plans, err := planengine.NewService(planengine.Config{HostAdoptions: repo, Repository: revisions, Observations: observations, Clock: time.Now, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if err != nil {
		t.Fatal(err)
	}
	requestNumber := 0
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) {
		requestNumber++
		return fmt.Sprintf("request-discovery-%d", requestNumber), nil
	})
	app, err := api.NewApplication(api.Config{Authority: authority, Authorizer: store.NewReadAuthorizer(authority), Reads: store.NewReadRepository(authority), Results: factory})
	if err != nil {
		t.Fatal(err)
	}
	policy := store.NewEffectiveAuthorizationRepository(authority)
	if err := api.RegisterDeclarationPlanOperations(app, api.DeclarationPlanConfig{Declarations: declarations, Plans: plans, Results: factory, Authorization: api.EffectiveAuthorizationConfig{Authorizer: authorization.NewEvaluator(policy), Recorder: policy, Clock: time.Now}}); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	target := generated.HostDiscoveryTarget{Schema: generated.SchemaIDHostDiscoveryTarget, SchemaVersion: "1.0.0", TargetID: "candidate-a", Revision: 1, Address: "127.0.0.1", Port: 2222, User: "inspect", HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey()))), ProfileID: "debian-13-amd64", CredentialReferenceID: "fixture-credential", MaterialVersion: "fixture-version", ExpectedOS: "debian", ExpectedVersion: "13", ExpectedArchitecture: "amd64"}
	target.ProfileID = "debian-13-amd64"
	dr := generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: "activate", IdempotencyKey: "fixture-target"}
	raw, _ := json.Marshal(dr)
	digest := hostdiscovery.Digest(dr)
	exec(`INSERT INTO host_discovery_drafts VALUES('fixture-target','candidate-a',1,0,'activate',?,?,'operator-a',0,0)`, digest, raw)
	hash := hostdiscovery.Digest("fixture")
	exec(`INSERT INTO declaration_revisions VALUES('fixture-declaration',1,'host.discovery-target',0,0,?,?,'draft',?,'now','operator-a','session-a')`, hash, hash, []byte(`{}`))
	exec(`INSERT INTO immutable_plans VALUES('fixture-plan',?,'fixture-declaration',1,1,0,?,?,?,?,?,?,'2026-01-01T00:00:00Z','2026-12-01T00:00:00Z')`, hash, hash, hash, hash, []byte(`{}`), "fixture", hash)
	exec(`INSERT INTO host_discovery_targets VALUES('candidate-a',1,'fixture-target','active','fixture-plan',0)`)
	now := clock().UTC().Truncate(time.Second)
	facts := []generated.HostDiscoveryFact{}
	for _, v := range []struct{ n, v, o string }{{"os.id", "debian", "os-release"}, {"os.version", "13", "os-release"}, {"architecture", "amd64", "architecture"}, {"product-serial", "synthetic-serial", "product-serial"}} {
		f := hostdiscovery.Fact(v.n, v.v, v.o)
		f.CapturedAt = now.Format(time.RFC3339)
		facts = append(facts, f)
	}
	obs := generated.HostObservation{Schema: generated.SchemaIDHostObservation, SchemaVersion: "1.0.0", ObservationID: "fixture-observation", TargetID: target.TargetID, TargetRevision: 1, TargetDigest: digest, Collector: hostdiscovery.CollectorID, CollectorVersion: "1.0.0", ObservedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(15 * time.Minute).Format(time.RFC3339), Status: "incomplete", Facts: facts, Blockers: []string{"hardening-unverified", "role-admission-unverified", "identity-class-unverified"}}
	obs.ContentDigest = hostdiscovery.Digest(obs)
	raw, _ = json.Marshal(obs)
	exec(`INSERT INTO host_discovery_attempts VALUES('fixture-observation','operator-a',?,?,'candidate-a',1,?,1,0,0,'later',?)`, hash, hash, digest, []byte(`{}`))
	exec(`INSERT INTO host_observations VALUES('fixture-observation','candidate-a',1,?,?,0,0)`, raw, hostdiscovery.Digest(obs))
	// removed
	//exec(`INSERT INTO effective_authorization_grants VALUES('adoption-grant','operator-a','control-plane-admin','author','host.adoption.prepare','host-discovery-target','candidate-a',NULL,1,'active','now','now')`)
	//exec(`INSERT INTO effective_authorization_grants VALUES('host-read','operator-a','control-plane-admin','read','host.read','host','synthetic-host',NULL,1,'active','now','now')`)
	req := generated.HostAdoptionRequest{Schema: generated.SchemaIDHostAdoptionRequest, SchemaVersion: "1.0.0", HostID: "synthetic-host", ObservationID: obs.ObservationID, ObservationDigest: obs.ContentDigest, IdempotencyKey: "adopt-one", Confirmation: generated.HostIdentityConfirmation{Schema: generated.SchemaIDHostIdentityConfirmation, SchemaVersion: "1.0.0", TargetRevision: 1, TargetDigest: digest, IdentityClass: "physical", IdentityKind: "product-serial", IdentityDigest: hostadoption.IdentityDigest("product-serial", "synthetic-serial"), ConfirmedAt: now.Format(time.RFC3339)}}
	exec(`UPDATE system_meta SET state_revision=1 WHERE id=1`)
	req.ExpectedStateRevision = 1
	request := func(method, path string, input any, authenticated bool) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(input)
		if input == nil {
			raw = nil
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		if input != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if authenticated {
			r = r.WithContext(identity.WithVerifiedPrincipal(r.Context(), principal))
		}
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		return w
	}
	decode := func(w *httptest.ResponseRecorder, out any) {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
		}
		var envelope struct {
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(w.Body.Bytes(), &envelope) != nil || json.Unmarshal(envelope.Data, out) != nil {
			t.Fatalf("invalid envelope %s", w.Body.String())
		}
	}

	if err := api.RegisterHostAdoptionOperations(app, api.HostAdoptionOperations{Hosts: repo, Declarations: declarations, Results: factory}); err != nil {
		t.Fatal(err)
	}
	declarationID := "host-adoption-" + hostadoption.Digest(req)[7:39]
	grant("declaration.author", "declaration", declarationID, "author")
	if mode == "prepare-denied" {
		exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE capability='host.adoption.prepare'`)
		w := request("POST", "/api/v1/host-adoptions/draft", req, true)
		if w.Code != http.StatusForbidden {
			t.Fatalf("prepare denial status %d", w.Code)
		}
		var drafts, hosts, failures int
		if err := db.QueryRow(`SELECT COUNT(*) FROM host_adoption_drafts`).Scan(&drafts); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM managed_hosts`).Scan(&hosts); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type='host.adoption.prepare-denied'`).Scan(&failures); err != nil {
			t.Fatal(err)
		}
		if drafts != 0 || hosts != 0 || failures != 1 {
			t.Fatalf("denial result drafts=%d hosts=%d audit=%d", drafts, hosts, failures)
		}
		var payload string
		if err := db.QueryRow(`SELECT CAST(canonical_payload AS TEXT) FROM audit_events WHERE event_type='host.adoption.prepare-denied'`).Scan(&payload); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(payload, "synthetic-serial") || strings.Contains(payload, "127.0.0.1") {
			t.Fatal("failure audit leaked facts")
		}
		return
	}
	var draft generated.HostAdoptionSubmission
	decode(request("POST", "/api/v1/host-adoptions/draft", req, true), &draft)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM managed_hosts`).Scan(&n); err != nil || n != 0 {
		t.Fatal("draft created host", err)
	}
	declaration, err := declarations.Get(ctx, draft.DeclarationID, 1)
	if err != nil {
		t.Fatal(err)
	}
	current, err := revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := observations.CurrentFingerprint(ctx, declaration.DeclarationID, declaration.Operations)
	if err != nil {
		t.Fatal(err)
	}
	created, err := plans.Create(ctx, planengine.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: "session-discovery"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: declaration.DeclarationID, DeclarationRevision: declaration.Revision, ExpectedStateRevision: current.StateRevision, ObservationFingerprint: fingerprint, IdempotencyKey: "plan-a", Extensions: declaration.Extensions})
	if err != nil {
		t.Fatal(err)
	}
	plan := created.Plan
	for _, g := range []struct{ action, cap, kind string }{{"acknowledge", "plan.acknowledge", "plan-target"}, {"execute", "host.adopt", "execution-target"}} {
		exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?,?,'human',1,'active','now','now')`, g.action+"-host", g.action, g.cap, g.kind, draft.DraftID)
	}
	if !strings.Contains(created.Readable, "Administrator attestation") || plan.HostAdoption == nil {
		t.Fatal("missing informed confirmation")
	}
	acknowledger, err := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(authority), Plans: lifecycleAcceptancePlanReader{plans}, Authorizer: lifecycleAcceptanceAuthorizer{}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	human := identity.Principal{ID: "operator-a", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
	card, err := acknowledger.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: "fixture-nonce"}, plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := acknowledger.Decide(ctx, acknowledgement.Candidate{Human: human, AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, Nonce: card.Nonce, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, ExpiresAt: mustAcceptanceTime(t, plan.ExpiresAt), DecidedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	effect := &runengine.HostAdoptionEffect{Repository: repo, Approvals: store.NewAcknowledgementRepository(authority)}
	engine, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(authority), Plans: plans, Admission: runengine.NewAdmissionGate(acknowledger, time.Now), Adapters: adapter.NewRegistry(), Core: runengine.CoreRouter{Adoption: effect}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	branch := "human"
	decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-discovery", PrincipalID: human.ID, Action: "execute", TargetID: plan.Operations[0].TargetID, Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, PlanDigest: plan.PlanDigest, DecidedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	submission := runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, IdempotencyKey: "run-a", Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: audit.Attribution{AuthenticatedPrincipalID: principal.ID, AuthenticatedPrincipalMethod: principal.Method, ResponsibleHumanPrincipalID: &human.ID}}
	if mode == "missing-ack" {
		submission.Acknowledgement = nil
	}
	if mode == "wrong-ack" {
		submission.Acknowledgement.AcknowledgementID = "wrong-ack"
	}
	applied, err := engine.Submit(ctx, submission)
	if mode != "success" {
		var hosts int
		if queryErr := db.QueryRow(`SELECT COUNT(*) FROM managed_hosts`).Scan(&hosts); queryErr != nil {
			t.Fatal(queryErr)
		}
		if err == nil || hosts != 0 {
			t.Fatalf("invalid acknowledgement accepted: %v hosts=%d", err, hosts)
		}
		return
	}

	if err != nil || applied.Status != "succeeded" {
		t.Fatalf("registration failed: %+v %v", applied, err)
	}
	var host generated.ManagedHost
	decode(request("GET", "/api/v1/hosts/synthetic-host", nil, true), &host)
	if host.Status != "adopted-unadmitted" || host.HostID != "synthetic-host" {
		t.Fatal("bad host status")
	}
	for _, table := range []string{"gate_applied_evidence", "gate_applied_profiles", "credential_reference_versions"} {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatal("registration changed authority", table, err)
		}
	}
	exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE capability='host.read'`)
	w := request("GET", "/api/v1/hosts/synthetic-host", nil, true)
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "synthetic-serial") {
		t.Fatal("revoked read disclosed host")
	}
}
