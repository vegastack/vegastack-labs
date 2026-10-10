//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
	"golang.org/x/crypto/ssh"
)

// Real API, SQLite, acknowledgement engine and protected key files. Only the
// initial identity/profile and Slack delivery authority are synthetic fixtures.
func TestPreloadedDiscoveryAPIApprovalAndRevocation(t *testing.T) {
	f := newPreloadedDiscoveryAcceptance(t)
	draft := f.draft("activate", f.target)
	f.denyDiscovery("draft-only")
	p := f.plan(draft)
	if w := f.execute(p); w.Code == http.StatusOK {
		t.Fatal("unacknowledged plan applied")
	}
	f.assertCount("host_discovery_targets", 0)
	f.approve(p)
	f.apply(p)
	if f.connections.Load() != 0 {
		t.Fatal("target activation contacted machine")
	}
	var observed generated.HostDiscoverySubmission
	f.decode(f.discover("approved"), &observed)
	if observed.Observation.Status != "untrusted" || !slices.Contains(observed.Observation.Blockers, "hardening-unverified") || f.commands.Load() != 10 || f.connections.Load() != 1 {
		t.Fatalf("discovery result status=%s commands=%d connections=%d", observed.Observation.Status, f.commands.Load(), f.connections.Load())
	}
	f.assertCount("host_observations", 1)
	if err := os.Remove(f.keyPath); err != nil {
		t.Fatal(err)
	}
	revoked := f.target
	revoked.Revision++
	revoke := f.plan(f.draft("revoke", revoked))
	f.approve(revoke)
	f.apply(revoke)
	f.denyDiscovery("revoked")
	if f.connections.Load() != 1 {
		t.Fatal("revocation or denied collection contacted machine")
	}
	f.assertCount("credential_reference_versions", 0)
	f.assertCount("credential_consumer_verifications", 0)
	f.assertCount("gate_applied_evidence", 0)
	f.assertCount("managed_hosts", 0)
	f.assertCount("gate_applied_profiles", 1)
}

func TestPreloadedDiscoveryAPIDenialsBeforeConnection(t *testing.T) {
	for _, scenario := range []string{"wrong-key", "missing-key", "loose-key", "revoked-grant", "changed-profile", "changed-epoch", "replaced-target"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPreloadedDiscoveryAcceptance(t)
			p := f.plan(f.draft("activate", f.target))
			f.approve(p)
			f.apply(p)
			switch scenario {
			case "wrong-key":
				raw, _ := preloadedReaderSyntheticKey(t)
				if err := os.WriteFile(f.keyPath, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-key":
				if err := os.Remove(f.keyPath); err != nil {
					t.Fatal(err)
				}
			case "loose-key":
				if err := os.Chmod(f.keyPath, 0644); err != nil {
					t.Fatal(err)
				}
			case "revoked-grant":
				f.exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE capability='host.discovery.collect'`)
			case "changed-profile":
				f.profile("profile-new", "different-profile", f.revision())
			case "changed-epoch":
				f.exec(`UPDATE system_meta SET recovery_epoch=recovery_epoch+1 WHERE id=1`)
			case "replaced-target":
				target := f.target
				target.Revision++
				p := f.plan(f.draft("activate", target))
				f.approve(p)
				f.apply(p)
			}
			f.denyDiscovery(scenario)
			if f.connections.Load() != 0 || f.commands.Load() != 0 {
				t.Fatal("preconnection denial contacted SSH peer")
			}
			f.assertCount("host_observations", 0)
			f.assertCount("credential_reference_versions", 0)
		})
	}
}

func TestPreloadedDiscoveryAPILegacyStillBlocked(t *testing.T) {
	f := newPreloadedDiscoveryAcceptance(t)
	target := f.target
	target.CredentialMode = nil
	target.CredentialPublicKeyDigest = nil
	p := f.plan(f.draft("activate", target))
	f.approve(p)
	if w := f.execute(p); w.Code == http.StatusOK {
		t.Fatal("legacy prerequisite bypassed by console gate")
	}
	f.assertCount("host_discovery_targets", 0)
	if f.connections.Load() != 0 {
		t.Fatal("legacy gate failure contacted machine")
	}
}

func TestPreloadedDiscoveryAPIPlanExpiry(t *testing.T) {
	t.Run("expired-activation", func(t *testing.T) {
		f := newPreloadedDiscoveryAcceptance(t)
		p := f.plan(f.draft("activate", f.target))
		f.approve(p)
		f.now = mustAcceptanceTime(t, p.ExpiresAt).Add(time.Second)
		if w := f.execute(p); w.Code == http.StatusOK {
			t.Fatal("expired plan applied")
		}
		f.assertCount("host_discovery_targets", 0)
		f.denyDiscovery("expired")
		if f.connections.Load() != 0 {
			t.Fatal("expired activation contacted peer")
		}
	})
	t.Run("applied-target-survives-historical-expiry", func(t *testing.T) {
		f := newPreloadedDiscoveryAcceptance(t)
		f.now = f.now.Add(-2 * time.Hour)
		p := f.plan(f.draft("activate", f.target))
		f.approve(p)
		f.apply(p)
		f.now = time.Now().UTC()
		if !f.now.After(mustAcceptanceTime(t, p.ExpiresAt)) {
			t.Fatal("fixture plan did not expire")
		}
		var observed generated.HostDiscoverySubmission
		f.decode(f.discover("after-expiry"), &observed)
		if observed.Observation.Status != "untrusted" || f.commands.Load() != 10 {
			t.Fatal("applied target stopped at historical plan expiry")
		}
	})
}

func TestPreloadedDiscoveryAPIRaceAfterDial(t *testing.T) {
	for _, scenario := range []string{"changed-key", "revoked-grant"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPreloadedDiscoveryAcceptance(t)
			p := f.plan(f.draft("activate", f.target))
			f.approve(p)
			f.apply(p)
			afterAccept := func() error {
				if scenario == "changed-key" {
					raw, _ := preloadedReaderSyntheticKey(t)
					return os.WriteFile(f.keyPath, raw, 0600)
				}
				_, err := f.db.Exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE capability='host.discovery.collect'`)
				return err
			}
			f.afterAccept.Store(&afterAccept)
			if w := f.discover("race"); w.Code == http.StatusOK {
				t.Fatal("raced material or authority allowed collection")
			}
			if f.connections.Load() != 1 || f.commands.Load() != 0 {
				t.Fatalf("race expected TCP but no commands: connections=%d commands=%d", f.connections.Load(), f.commands.Load())
			}
			f.assertCount("host_observations", 0)
			f.assertCount("host_discovery_failures", 1)
		})
	}
}

func TestPreloadedDiscoveryAPIAcknowledgementGrantRevocation(t *testing.T) {
	for _, phase := range []string{"before-request", "before-decision"} {
		t.Run(phase, func(t *testing.T) {
			f := newPreloadedDiscoveryAcceptance(t)
			p := f.plan(f.draft("activate", f.target))
			human := identity.Principal{ID: "operator-a", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
			scope := acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: "fixture-" + p.PlanID}
			revoke := func() {
				f.exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE action='acknowledge' AND capability='plan.acknowledge' AND resource_id=?`, p.Operations[0].TargetID)
			}
			if phase == "before-request" {
				revoke()
				if _, err := f.ack.Request(context.Background(), scope, p.PlanID); err == nil {
					t.Fatal("revoked acknowledgement request accepted")
				}
				f.assertCount("acknowledgement_requests", 0)
			} else {
				card, err := f.ack.Request(context.Background(), scope, p.PlanID)
				if err != nil {
					t.Fatal(err)
				}
				revoke()
				_, err = f.ack.Decide(context.Background(), acknowledgement.Candidate{Human: human, AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove, PlanID: p.PlanID, PlanDigest: p.PlanDigest, TargetDigest: p.Binding.TargetDigest, ReasonDigest: p.Binding.ReasonDigest, Nonce: card.Nonce, StateRevision: p.Binding.StateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch, ExpiresAt: mustAcceptanceTime(t, p.ExpiresAt), DecidedAt: f.now})
				if err == nil {
					t.Fatal("revoked acknowledgement decision accepted")
				}
			}
			var approved int
			if err := f.db.QueryRow(`SELECT COUNT(*) FROM acknowledgement_requests WHERE status='approved'`).Scan(&approved); err != nil || approved != 0 {
				t.Fatalf("approved rows=%d err=%v", approved, err)
			}
			if w := f.execute(p); w.Code == http.StatusOK {
				t.Fatal("revoked acknowledgement enabled apply")
			}
			f.assertCount("host_discovery_targets", 0)
			f.denyDiscovery(phase)
			if f.connections.Load() != 0 {
				t.Fatal("revoked acknowledgement contacted peer")
			}
		})
	}
}

func TestPreloadedDiscoveryAPIExpiryAfterAdmission(t *testing.T) {
	for _, action := range []string{"activate", "revoke"} {
		t.Run(action, func(t *testing.T) {
			f := newPreloadedDiscoveryAcceptance(t)
			target := f.target
			expectedRows := 0
			if action == "revoke" {
				p := f.plan(f.draft("activate", target))
				f.approve(p)
				f.apply(p)
				target.Revision++
				expectedRows = 1
			}
			p := f.plan(f.draft(action, target))
			f.approve(p)
			expiry := mustAcceptanceTime(t, p.ExpiresAt)
			f.now = expiry.Add(-2 * time.Second)
			crossed := false
			f.afterAdmission = func(leaseDeadline time.Time) {
				crossed = true
				f.now = expiry.Add(time.Second)
				if !f.now.Before(leaseDeadline) {
					t.Fatal("expiry fixture also expired lease")
				}
			}
			w := f.execute(p)
			if !crossed {
				t.Fatal("did not reach admitted leased execution")
			}
			if w.Code == http.StatusOK {
				t.Fatal("plan expired after admission still applied")
			}
			f.assertCount("host_discovery_targets", expectedRows)
			var status string
			if err := f.db.QueryRow(`SELECT status FROM plan_runs WHERE plan_id=?`, p.PlanID).Scan(&status); err != nil || status != "failed" {
				t.Fatalf("run status=%s err=%v", status, err)
			}
			var failures int
			if err := f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type='run.step-failed-before-effect'`).Scan(&failures); err != nil || failures < 1 {
				t.Fatalf("failure audit=%d err=%v", failures, err)
			}
			if f.connections.Load() != 0 {
				t.Fatal("expired target operation contacted peer")
			}
		})
	}
}

type preloadedDiscoveryAcceptance struct {
	t              *testing.T
	now            time.Time
	db             *sql.DB
	authority      *store.Store
	app            *api.Application
	ack            *acknowledgement.Service
	target         generated.HostDiscoveryTarget
	keyPath        string
	commands       *atomic.Int32
	connections    atomic.Int32
	afterAccept    atomic.Pointer[func() error]
	afterAdmission func(time.Time)
	sequence       int
}

func newPreloadedDiscoveryAcceptance(t *testing.T) *preloadedDiscoveryAcceptance {
	t.Helper()
	f := &preloadedDiscoveryAcceptance{t: t, now: time.Now().UTC()}
	started := time.Now()
	clock := func() time.Time { return f.now.Add(time.Since(started)) }
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.db")
	var err error
	f.authority, err = store.Open(context.Background(), store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Getuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.authority.Close() })
	f.db, err = sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.db.Close() })
	f.exec(`INSERT INTO effective_authorization_principals VALUES('operator-a','human','active',1,'now','now')`)
	f.exec(`INSERT INTO read_principals VALUES('operator-a','active',1,'now','now')`)
	f.exec(`UPDATE system_meta SET state_revision=1 WHERE id=1`)
	f.profile("profile-initial", "portable-test", 1)
	for _, cap := range []string{"host.discovery.collect", "host.discovery.read"} {
		f.grant(cap, "host-discovery-target", "candidate-a", "read", nil)
	}
	f.grant("host.discovery.target.prepare", "host-discovery-target", "candidate-a", "author", nil)
	f.exec(`INSERT INTO read_grants VALUES('operator-a','host.discovery.read','host-discovery-target','candidate-a',1,'active','now','now')`)
	target, raw, commands := discoveryAcceptancePeer(t, "13.6")
	f.commands = commands
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(signer.PublicKey().Marshal())
	digest, mode := "sha256:"+hex.EncodeToString(sum[:]), "preloaded-discovery"
	target.CredentialMode = &mode
	target.CredentialPublicKeyDigest = &digest
	target.Port = f.forwardPeer(target.Port)
	f.target = target
	f.keyPath = filepath.Join(directory, nativecredential.LoadedNameForVersion(hostdiscovery.Consumer, target.CredentialReferenceID, target.MaterialVersion))
	if err := os.WriteFile(f.keyPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	repository := store.NewHostDiscoveryRepository(f.authority)
	revisions := store.NewPlanRepository(f.authority)
	declarations, err := change.NewService(store.NewDeclarationRepository(f.authority), clock)
	if err != nil {
		t.Fatal(err)
	}
	observations, err := planengine.NewStateObservationReader(revisions)
	if err != nil {
		t.Fatal(err)
	}
	plans, err := planengine.NewService(planengine.Config{HostDiscoveryTargets: repository, Repository: revisions, Observations: observations, Clock: clock, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if err != nil {
		t.Fatal(err)
	}
	var ids atomic.Int64
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return fmt.Sprintf("preloaded-request-%d", ids.Add(1)), nil })
	f.app, err = api.NewApplication(api.Config{Authority: f.authority, Authorizer: store.NewReadAuthorizer(f.authority), Reads: store.NewReadRepository(f.authority), Results: factory})
	if err != nil {
		t.Fatal(err)
	}
	policy := store.NewEffectiveAuthorizationRepository(f.authority)
	effective := api.EffectiveAuthorizationConfig{Authorizer: authorization.NewEvaluator(policy), Recorder: policy, Clock: clock}
	if err := api.RegisterDeclarationPlanOperations(f.app, api.DeclarationPlanConfig{Declarations: declarations, Plans: plans, Results: factory, Authorization: effective}); err != nil {
		t.Fatal(err)
	}
	registry := adapter.NewRegistry()
	if err := registerHostDiscovery(f.app, f.authority, registry, declarations, factory, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	f.ack, err = acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(f.authority), Plans: lifecycleAcceptancePlanReader{plans}, Authorizer: authorization.NewEvaluator(policy), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	// Align the simulated clock with a real timeout of the same remaining lease
	// duration; backdated history must not disable or prematurely expire leases.
	engine, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(f.authority), Plans: plans, Admission: runengine.NewAdmissionGate(f.ack, clock), LeaseContext: func(ctx context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
		if f.afterAdmission != nil {
			f.afterAdmission(deadline)
		}
		return context.WithTimeout(ctx, deadline.Sub(clock()))
	}, Adapters: registry, Core: runengine.CoreRouter{DiscoveryTarget: &runengine.HostDiscoveryTargetEffect{Repository: repository, Approvals: store.NewAcknowledgementRepository(f.authority), RecoveryPrecheck: discoveryConsoleGate{targets: repository, fallback: runengine.UnavailableGateVerifier{}}}}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if err := api.RegisterRunOperations(f.app, api.RunOperationConfig{Runs: engine, Plans: plans, Acknowledgements: f.ack, Results: factory, Authorization: effective}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *preloadedDiscoveryAcceptance) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.db.Exec(q, args...); err != nil {
		f.t.Fatal(err)
	}
}
func (f *preloadedDiscoveryAcceptance) grant(cap, kind, id, action string, branch any) {
	f.t.Helper()
	var count int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM effective_authorization_grants WHERE principal_id='operator-a' AND role_id='control-plane-admin' AND action=? AND capability=? AND resource_kind=? AND resource_id=? AND branch IS ? AND grant_revision=1 AND status='active'`, action, cap, kind, id, branch).Scan(&count); err != nil {
		f.t.Fatal(err)
	}
	if count == 1 {
		return
	}
	if count != 0 {
		f.t.Fatal("ambiguous fixture grant")
	}
	f.exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?,?,?,1,'active','now','now')`, "grant-"+hostdiscovery.Digest([]string{cap, id})[7:25], action, cap, kind, id, branch)
}
func (f *preloadedDiscoveryAcceptance) profile(binding, profile string, revision int64) {
	f.t.Helper()
	f.exec(`INSERT INTO gate_applied_profiles VALUES(?,?,'1.0.0','fixture-policy','1.0.0',?, ?,0,'fixture-profile',1,'fixture-profile-plan',?,'fixture-profile-run','fixture-profile-step','fixture-profile-lease','operator-a','now')`, binding, profile, []byte(`[]`), revision, hostdiscovery.Digest("synthetic-profile"))
}
func (f *preloadedDiscoveryAcceptance) revision() int64 {
	f.t.Helper()
	var r int64
	if err := f.db.QueryRow(`SELECT state_revision FROM system_meta WHERE id=1`).Scan(&r); err != nil {
		f.t.Fatal(err)
	}
	return r
}
func (f *preloadedDiscoveryAcceptance) request(method, path string, input any) *httptest.ResponseRecorder {
	f.t.Helper()
	var raw []byte
	if input != nil {
		var err error
		raw, err = json.Marshal(input)
		if err != nil {
			f.t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	if input != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	r = r.WithContext(identity.WithVerifiedPrincipal(r.Context(), identity.Principal{ID: "operator-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
	w := httptest.NewRecorder()
	f.app.ServeHTTP(w, r)
	return w
}
func (f *preloadedDiscoveryAcceptance) decode(w *httptest.ResponseRecorder, out any) {
	f.t.Helper()
	if w.Code != http.StatusOK {
		f.t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	var result generated.RunResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		f.t.Fatal(err)
	}
	if err := json.Unmarshal(result.Data, out); err != nil {
		f.t.Fatal(err)
	}
}
func (f *preloadedDiscoveryAcceptance) draft(action string, target generated.HostDiscoveryTarget) generated.HostDiscoveryTargetDraftSubmission {
	f.t.Helper()
	f.sequence++
	req := generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: action, ExpectedTargetRevision: target.Revision - 1, ExpectedStateRevision: f.revision(), IdempotencyKey: fmt.Sprintf("draft-%d", f.sequence), ConsoleConfirmation: &generated.HostDiscoveryConsoleConfirmation{Schema: generated.SchemaIDHostDiscoveryConsoleConfirmation, SchemaVersion: "1.0.0", TargetDigest: hostdiscovery.Digest(target), Method: "administrator-verified-console"}}
	if target.CredentialMode == nil {
		req.ConsoleConfirmation = nil
	}
	id := "discovery-draft-" + hostdiscovery.Digest(req)[7:39]
	f.grant("declaration.author", "declaration", id, "author", nil)
	var draft generated.HostDiscoveryTargetDraftSubmission
	f.decode(f.request("POST", "/api/v1/host-discovery-targets/draft", req), &draft)
	return draft
}
func (f *preloadedDiscoveryAcceptance) plan(d generated.HostDiscoveryTargetDraftSubmission) generated.Plan {
	f.t.Helper()
	f.grant("declaration.read", "declaration", d.DeclarationID+":1", "read", nil)
	f.grant("plan.author", "declaration", d.DeclarationID, "author", nil)
	f.exec(`INSERT INTO read_grants VALUES('operator-a','declaration.read','declaration',?,1,'active','now','now')`, d.DeclarationID+":1")
	var prep generated.PlanPreparation
	f.decode(f.request("GET", "/api/v1/declarations/"+d.DeclarationID+"/revisions/1/plan-preparation", nil), &prep)
	req := generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: d.DeclarationID, DeclarationRevision: 1, ExpectedStateRevision: prep.ExpectedStateRevision, RecoveryEpoch: prep.RecoveryEpoch, ObservationFingerprint: prep.ObservationFingerprint, IdempotencyKey: "plan-" + d.DraftID, Extensions: []generated.ContractExtension{}}
	var presentation generated.PlanPresentation
	f.decode(f.request("POST", "/api/v1/declarations/"+d.DeclarationID+"/plans", req), &presentation)
	p := presentation.Plan
	if p.HostDiscoveryTarget != nil {
		var readable generated.HostDiscoveryTargetDraftRequest
		_, section, found := strings.Cut(presentation.ReadablePlan, "Exact target and administrator confirmation: ")
		raw, _, _ := strings.Cut(section, "\n")
		if !found || json.Unmarshal([]byte(raw), &readable) != nil || hostdiscovery.Digest(readable) != hostdiscovery.Digest(*p.HostDiscoveryTarget) || readable.ConsoleConfirmation == nil || readable.ConsoleConfirmation.TargetDigest != hostdiscovery.Digest(readable.Target) {
			f.t.Fatal("plan views omit exact target confirmation")
		}
	}
	f.grant("plan.acknowledge", "plan-target", authorization.ExecutionResourceIDs(p, p.Operations[0])[0], "acknowledge", "human")
	f.grant(p.Operations[0].OperationType, "execution-target", authorization.ExecutionResourceIDs(p, p.Operations[0])[0], "execute", "human")
	return p
}
func (f *preloadedDiscoveryAcceptance) approve(p generated.Plan) {
	f.t.Helper()
	human := identity.Principal{ID: "operator-a", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
	card, err := f.ack.Request(context.Background(), acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: "fixture-" + p.PlanID}, p.PlanID)
	if err != nil {
		f.t.Fatal(err)
	}
	_, err = f.ack.Decide(context.Background(), acknowledgement.Candidate{Human: human, AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove, PlanID: p.PlanID, PlanDigest: p.PlanDigest, TargetDigest: p.Binding.TargetDigest, ReasonDigest: p.Binding.ReasonDigest, Nonce: card.Nonce, StateRevision: p.Binding.StateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch, ExpiresAt: mustAcceptanceTime(f.t, p.ExpiresAt), DecidedAt: f.now})
	if err != nil {
		f.t.Fatal(err)
	}
}
func (f *preloadedDiscoveryAcceptance) execute(p generated.Plan) *httptest.ResponseRecorder {
	return f.request("POST", "/api/v1/plans/"+p.PlanID+"/execute", generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, RecoveryEpoch: p.Binding.RecoveryEpoch, IdempotencyKey: "run-" + p.PlanID, Extensions: []generated.ContractExtension{}})
}
func (f *preloadedDiscoveryAcceptance) apply(p generated.Plan) {
	f.t.Helper()
	var run generated.RunPresentation
	f.decode(f.execute(p), &run)
	if run.Run.Status != "succeeded" {
		f.t.Fatalf("activation status %s", run.Run.Status)
	}
}
func (f *preloadedDiscoveryAcceptance) discover(key string) *httptest.ResponseRecorder {
	return f.request("POST", "/api/v1/host-observations", generated.HostDiscoveryRequest{Schema: generated.SchemaIDHostDiscoveryRequest, SchemaVersion: "1.0.0", TargetID: f.target.TargetID, TargetRevision: f.target.Revision, ExpectedStateRevision: f.revision(), RecoveryEpoch: f.target.RecoveryEpoch, IdempotencyKey: key})
}
func (f *preloadedDiscoveryAcceptance) denyDiscovery(key string) {
	f.t.Helper()
	if w := f.discover(key); w.Code == http.StatusOK {
		f.t.Fatal("discovery denial accepted")
	}
}
func (f *preloadedDiscoveryAcceptance) assertCount(table string, want int) {
	f.t.Helper()
	var got int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&got); err != nil {
		f.t.Fatal(err)
	}
	if got != want {
		f.t.Fatalf("%s rows %d, want %d", table, got, want)
	}
}

// Forward only loopback fixture traffic, counting actual TCP accepts and making
// key/grant replacement deterministic after Dial and before SSH authentication.
func (f *preloadedDiscoveryAcceptance) forwardPeer(port int64) int64 {
	f.t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.t.Fatal(err)
	}
	done := make(chan struct{})
	var active atomic.Pointer[net.Conn]
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		active.Store(&connection)
		defer connection.Close()
		f.connections.Add(1)
		if callback := f.afterAccept.Load(); callback != nil {
			if err := (*callback)(); err != nil {
				f.t.Error(err)
				return
			}
		}
		peer, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			f.t.Error(err)
			return
		}
		defer peer.Close()
		copied := make(chan struct{})
		go func() { _, _ = io.Copy(peer, connection); _ = peer.Close(); close(copied) }()
		_, _ = io.Copy(connection, peer)
		_ = connection.Close()
		<-copied
	}()
	f.t.Cleanup(func() {
		_ = listener.Close()
		if c := active.Load(); c != nil {
			_ = (*c).Close()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			f.t.Error("forwarding peer did not stop")
		}
	})
	return int64(listener.Addr().(*net.TCPAddr).Port)
}
