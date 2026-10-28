//go:build linux

package server

import (
	"bytes"
	"context"
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
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Real SQLite, API authorization, declaration, plan, acknowledgement, run and
// lease storage. Only machine identity and OS pre/post-observation are fixtures;
// this exercises no root installer and conveys no native qualification.
func TestControllerSetupCurrentAcknowledgementClaimAndReceipt(t *testing.T) {
	for _, variant := range []string{"success", "observer-mismatch", "stale-authority", "expired-lease"} {
		t.Run(variant, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			os.Chmod(dir, 0700)
			path := filepath.Join(dir, "control.db")
			now := time.Now().UTC().Truncate(time.Second)
			clock := func() time.Time { return now }
			cfg := store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock}
			if runtime.GOOS != "linux" {
				cfg.Filesystem = notificationWorkflowFS{}
			}
			s, e := store.Open(ctx, cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			db, e := sql.Open("sqlite3", path)
			if e != nil {
				t.Fatal(e)
			}
			defer db.Close()
			exec := func(q string, a ...any) {
				t.Helper()
				if _, e := db.Exec(q, a...); e != nil {
					t.Fatal(e)
				}
			}
			exec(`UPDATE system_meta SET state_revision=1 WHERE id=1`)
			exec(`INSERT INTO effective_authorization_principals VALUES('operator-a','human','active',1,'now','now')`)
			exec(`INSERT INTO read_principals VALUES('operator-a','active',1,'now','now')`)
			grant := func(id, action, cap, kind, target, branch string) {
				var b any
				if branch != "" {
					b = branch
				}
				exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?,?,?,1,'active','now','now')`, id, action, cap, kind, target, b)
			}
			grant("execute", "execute", "controller.setup.bootstrap", "execution-target", "synthetic-controller", "human")
			policy, _, _, _, _ := controllerPilotFixture()
			a, e := s.CurrentAuthority(ctx)
			if e != nil {
				t.Fatal(e)
			}
			policy.ControllerInstanceID = a.InstanceID
			policy.ExpiresAt = now.Add(time.Hour).Format(time.RFC3339)
			caps, _ := json.Marshal([]string{controllerSetupPilotCapability(policy)})
			exec(`INSERT INTO gate_applied_profiles VALUES('pilot-profile','profile-a','1.0.0','pilot-policy','1.0.0',?,1,0,'fixture-profile',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, caps, hostaction.Digest("profile"))
			revisions := store.NewPlanRepository(s)
			declarations, e := change.NewService(store.NewDeclarationRepository(s), clock)
			if e != nil {
				t.Fatal(e)
			}
			observations, e := planengine.NewStateObservationReader(revisions)
			if e != nil {
				t.Fatal(e)
			}
			plans, e := planengine.NewService(planengine.Config{Repository: revisions, Observations: observations, Clock: clock, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "control-plane", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
			if e != nil {
				t.Fatal(e)
			}
			input := `{"synthetic":"fixed-installer-input"}`
			d, e := declarations.Revise(ctx, change.AuthorScope{PrincipalID: "operator-a", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "fixture-session"}, generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: "controller-foundation", DeclarationType: "controller.setup", ExpectedRevision: 1, ExpectedStateRevision: 1, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "foundation", OperationType: "controller.setup.bootstrap", AdapterID: "core.controller-setup", TargetID: policy.HostID, InputDigest: hostaction.BytesDigest([]byte(input)), ArtifactDigest: hostaction.Digest(policy)}}, ReasonDigest: hostaction.Digest("exact foundation setup"), Extensions: []generated.ContractExtension{}})
			if e != nil {
				t.Fatal(e)
			}
			fingerprint, e := observations.CurrentFingerprint(ctx, d.Document.DeclarationID, d.Document.Operations)
			if e != nil {
				t.Fatal(e)
			}
			planned, e := plans.Create(ctx, planengine.AuthorScope{PrincipalID: "operator-a", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "fixture-session"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: d.Document.DeclarationID, DeclarationRevision: 1, ExpectedStateRevision: d.Document.StateRevision, ObservationFingerprint: fingerprint, IdempotencyKey: "controller-plan", Extensions: []generated.ContractExtension{}})
			if e != nil {
				t.Fatal(e)
			}
			p := planned.Plan
			ack, e := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(s), Plans: lifecycleAcceptancePlanReader{plans}, Authorizer: lifecycleAcceptanceAuthorizer{}, Clock: clock})
			if e != nil {
				t.Fatal(e)
			}
			runsRepo := store.NewRunRepository(s)
			engine, e := runengine.NewEngine(runengine.Config{Repository: runsRepo, Plans: plans, Admission: runengine.NewAdmissionGate(ack, clock), Adapters: adapter.NewRegistry(), Clock: clock})
			if e != nil {
				t.Fatal(e)
			}
			counter := 0
			factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { counter++; return fmt.Sprintf("controller-request-%d", counter), nil })
			app, e := api.NewApplication(api.Config{Authority: s, Authorizer: store.NewReadAuthorizer(s), Reads: store.NewReadRepository(s), Results: factory})
			if e != nil {
				t.Fatal(e)
			}
			auth := store.NewEffectiveAuthorizationRepository(s)
			authConfig := api.EffectiveAuthorizationConfig{Authorizer: authorization.NewEvaluator(auth), Recorder: auth, Clock: clock}
			verifier := newControllerSetupPilotVerifier(s, store.NewGateRepository(s), &policy, clock)
			verifier.machine = func() (string, error) { return policy.ControllerMachineIDDigest, nil }
			profile := serverconfig.Profile{PrincipalBindings: []principal.Binding{{UID: uint32(policy.AdministratorUID), PrincipalID: policy.AdministratorPrincipalID}}}
			source := &controllerSetupClaims{authority: s, runs: runsRepo, plans: revisions, verifier: verifier, profile: profile, clock: clock}
			effects, observes := 0, 0
			source.validateInput = func(_ context.Context, plan generated.Plan, raw string) error {
				if raw != input || plan.Operations[0].InputDigest != hostaction.BytesDigest([]byte(raw)) {
					return actionFailure()
				}
				return nil
			}
			source.preconditions = func(context.Context, generated.Plan, string) error { effects++; return nil }
			resultDigest := hostaction.Digest("actual fixed metadata")
			source.observe = func(context.Context, generated.Plan, string) (string, error) {
				observes++
				if variant == "observer-mismatch" {
					return hostaction.Digest("wrong files"), nil
				}
				return resultDigest, nil
			}
			if e = api.RegisterRunOperations(app, api.RunOperationConfig{Runs: engine, Plans: plans, Acknowledgements: ack, Results: factory, Authorization: authConfig}); e != nil {
				t.Fatal(e)
			}
			if e = api.RegisterControllerSetupOperations(app, api.ControllerSetupOperations{Runs: api.RunOperationConfig{Runs: controllerSetupRuns{engine}, Plans: plans, Acknowledgements: ack, Results: factory, Authorization: authConfig}, Lifecycle: source}); e != nil {
				t.Fatal(e)
			}
			principal := identity.Principal{ID: "operator-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
			request := func(method string, q any, who identity.Principal) *httptest.ResponseRecorder {
				raw, _ := json.Marshal(q)
				r := httptest.NewRequest("POST", "/api/v1/controller-setup/"+method, bytes.NewReader(raw)).WithContext(identity.WithVerifiedPrincipal(ctx, who))
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				app.ServeHTTP(w, r)
				return w
			}
			claimRequest := generated.ControllerSetupClaimRequest{Schema: generated.SchemaIDControllerSetupClaimRequest, SchemaVersion: "1.0.0", Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, IdempotencyKey: "controller-run", Extensions: []generated.ContractExtension{}}, InputJSON: input}
			for _, who := range []identity.Principal{{ID: principal.ID, Method: identity.CloudflareAccessMethod, Kind: identity.PrincipalHuman}, {ID: principal.ID, Method: "constrained-ssh", Kind: identity.PrincipalHuman}, {ID: "other-human", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}} {
				if w := request("claim", claimRequest, who); w.Code == 200 {
					t.Fatal("non-local or wrong admin accepted")
				}
			}
			if w := request("claim", claimRequest, principal); w.Code == 200 {
				t.Fatal("missing Slack acknowledgement accepted")
			}
			if effects != 0 {
				t.Fatal("unapproved claim reached preconditions")
			}
			human := identity.Principal{ID: "human-a", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
			card, e := ack.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: "controller-nonce"}, p.PlanID)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = ack.Decide(ctx, acknowledgement.Candidate{Human: human, AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove, PlanID: p.PlanID, PlanDigest: p.PlanDigest, TargetDigest: p.Binding.TargetDigest, ReasonDigest: p.Binding.ReasonDigest, Nonce: card.Nonce, StateRevision: p.Binding.StateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch, ExpiresAt: mustAcceptanceTime(t, p.ExpiresAt), DecidedAt: now}); e != nil {
				t.Fatal(e)
			}
			bad := claimRequest
			bad.InputJSON = "{}"
			if w := request("claim", bad, principal); w.Code == 200 {
				t.Fatal("wrong input accepted")
			}
			w := request("claim", claimRequest, principal)
			if w.Code != 200 {
				t.Fatalf("claim HTTP %d: %s", w.Code, w.Body.String())
			}
			var env struct {
				Data generated.ControllerSetupClaim `json:"data"`
			}
			if json.Unmarshal(w.Body.Bytes(), &env) != nil {
				t.Fatal(w.Body.String())
			}
			claim := env.Data
			if effects != 1 || claim.Run.Status != "running" || claim.ClaimDigest == "" {
				t.Fatalf("invalid claim %+v effects%d", claim, effects)
			}
			if w = request("claim", claimRequest, principal); w.Code == 200 {
				t.Fatal("claimed effect replayed")
			}
			if effects != 1 {
				t.Fatal("duplicate claim reentered preconditions")
			}
			receipt := generated.ControllerSetupReceiptRequest{Schema: generated.SchemaIDControllerSetupReceiptRequest, SchemaVersion: "1.0.0", ClaimDigest: claim.ClaimDigest, RunID: claim.Run.RunID, LeaseID: claim.Lease.LeaseID, ResultDigest: resultDigest, InputJSON: input, Status: "installed-awaiting-native-verification"}
			badReceipt := receipt
			badReceipt.ClaimDigest = hostaction.Digest("forged claim")
			if w = request("receipt", badReceipt, principal); w.Code == 200 {
				t.Fatal("forged receipt accepted")
			}
			if observes != 0 {
				t.Fatal("forgery reached observation")
			}
			if variant == "stale-authority" {
				exec(`UPDATE system_meta SET state_revision=state_revision+1 WHERE id=1`)
			}
			if variant == "expired-lease" {
				now = now.Add(61 * time.Second)
			}
			w = request("receipt", receipt, principal)
			if variant == "stale-authority" || variant == "expired-lease" {
				if w.Code == 200 || observes != 0 {
					t.Fatal("stale receipt reached observer", w.Body.String())
				}
				return
			}
			if w.Code != 200 {
				t.Fatalf("receipt HTTP%d %s", w.Code, w.Body.String())
			}
			var runEnv struct {
				Data generated.Run `json:"data"`
			}
			json.Unmarshal(w.Body.Bytes(), &runEnv)
			expected := "succeeded"
			if variant == "observer-mismatch" {
				expected = "partial"
			}
			if runEnv.Data.Status != expected || observes != 1 {
				t.Fatalf("receipt outcome %+v", runEnv.Data)
			}
			if w = request("receipt", receipt, principal); w.Code == 200 {
				t.Fatal("receipt replay accepted")
			}
		})
	}
}

func TestControllerSetupRecoveryUsesOnlyInitialAdminExclusiveServerSnapshot(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "control.db")
	cfg := store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test"}
	if runtime.GOOS != "linux" {
		cfg.Filesystem = notificationWorkflowFS{}
	}
	s, e := store.Open(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	db, e := sql.Open("sqlite3", path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec(`INSERT INTO effective_authorization_principals VALUES('operator-a','human','active',1,'now','now')`); e != nil {
		t.Fatal(e)
	}
	human := "operator-a"
	digest := hostaction.Digest("setup-audit")
	_, e = s.AppendOperationalAudit(ctx, store.OperationalAuditRequest{Expected: store.RevisionToken{}, Idempotency: audit.IntentKey{Scope: "controller-recovery-fixture", KeyDigest: audit.Fingerprint(digest), RequestDigest: audit.Fingerprint(digest)}, Event: audit.EventDraft{Type: "control.initialized", CorrelationID: "setup-fixture", Attribution: audit.Attribution{AuthenticatedPrincipalID: human, AuthenticatedPrincipalMethod: identity.SlackSocketModeMethod, ResponsibleHumanPrincipalID: &human}, Target: audit.Target{Kind: "acknowledgement-authority", ID: "fixture-authority"}}})
	if e != nil {
		t.Fatal(e)
	}
	image := filepath.Join(dir, "controller-pilot-recovery.db")
	source := controllerSetupRecovery{authority: s, profile: serverconfig.Profile{SocketOwnerUID: uint32(os.Geteuid()), PrincipalBindings: []principal.Binding{{UID: uint32(os.Geteuid()), PrincipalID: human}}}, destination: image}
	q := generated.ControllerSetupRecoveryRequest{Schema: generated.SchemaIDControllerSetupRecoveryRequest, SchemaVersion: "1.0.0"}
	p := identity.Principal{ID: human, Kind: identity.PrincipalHuman, Method: identity.LocalOSPeerMethod}
	for _, wrong := range []identity.Principal{{ID: "someone-else", Kind: identity.PrincipalHuman, Method: identity.LocalOSPeerMethod}, {ID: human, Kind: identity.PrincipalHuman, Method: identity.CloudflareAccessMethod}} {
		if _, e = source.PrepareRecovery(ctx, q, wrong); e == nil {
			t.Fatal("unbound caller created snapshot")
		}
	}
	if _, e = os.Stat(image); !os.IsNotExist(e) {
		t.Fatal("denied preparation left image")
	}
	stale := q
	stale.ExpectedStateRevision = 1
	if _, e = source.PrepareRecovery(ctx, stale, p); e == nil {
		t.Fatal("stale preparation accepted")
	}
	got, e := source.PrepareRecovery(ctx, q, p)
	if e != nil || got.ImageDigest == "" || got.ControllerInstanceID == "" {
		t.Fatal(got, e)
	}
	raw, e := os.ReadFile(image)
	if e != nil || hostaction.BytesDigest(raw) != got.ImageDigest {
		t.Fatal("not actual snapshot hash", e)
	}
	if _, e = source.PrepareRecovery(ctx, q, p); e == nil {
		t.Fatal("snapshot overwritten")
	}
	after, _ := os.ReadFile(image)
	if !bytes.Equal(raw, after) {
		t.Fatal("existing image modified")
	}
}
