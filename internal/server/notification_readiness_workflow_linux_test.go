//go:build linux

package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/githubalerts"
	"github.com/vegastack/vegastack-labs/internal/adapter/slackalerts"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/operations"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// Only platform filesystem probes and credential/provider wire values are
// synthetic. SQLite, declarations, plans, acknowledgement, executor, receipt
// persistence, evidence application and the production G-011 verifier are real.
// This does not exercise native credential custody or live provider acceptance.
type notificationWorkflowFS struct{}

func (notificationWorkflowFS) InspectParent(context.Context, string, uint32) (store.FileIdentity, error) {
	return store.FileIdentity{Device: 1, Inode: 1, Links: 1, Local: true, Mode: 0700}, nil
}
func (notificationWorkflowFS) CreateDatabase(_ context.Context, p string, u uint32) (store.FileIdentity, error) {
	f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		return store.FileIdentity{}, e
	}
	e = f.Close()
	return store.FileIdentity{Device: 1, Inode: 2, Links: 1, UID: u, Local: true, Mode: 0600}, e
}
func (notificationWorkflowFS) InspectDatabase(context.Context, string, uint32) (store.FileIdentity, error) {
	return store.FileIdentity{Device: 1, Inode: 2, Links: 1, Local: true, Mode: 0600}, nil
}
func (notificationWorkflowFS) AcquireWriterLock(context.Context, string, uint32) (io.Closer, error) {
	return io.NopCloser(strings.NewReader("")), nil
}
func (notificationWorkflowFS) SameFile(a, b store.FileIdentity) bool {
	return a.Device == b.Device && a.Inode == b.Inode
}
func (notificationWorkflowFS) SyncDatabase(_ context.Context, p string, _ store.FileIdentity) error {
	f, e := os.OpenFile(p, os.O_RDWR, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}

type notificationWorkflowPlanReader struct{ p *planengine.Service }

func (r notificationWorkflowPlanReader) Get(c context.Context, id string) (generated.Plan, error) {
	v, e := r.p.Get(c, id)
	return v.Plan, e
}
func (r notificationWorkflowPlanReader) ValidateCurrent(c context.Context, p generated.Plan) error {
	return r.p.ValidateCurrent(c, p)
}

type notificationWorkflowResolver struct{ calls int }

func (r *notificationWorkflowResolver) Resolve(_ context.Context, b credentialref.StepBinding) (*credentialref.Value, error) {
	r.calls++
	if b.ConsumerID != operations.ReadinessAdapter {
		return nil, fmt.Errorf("wrong consumer")
	}
	switch b.PurposeID {
	case operations.ReadinessGithubPurpose:
		return credentialref.NewValue([]byte("synthetic-github-value"))
	case operations.ReadinessSlackPurpose:
		return credentialref.NewValue([]byte("https://hooks.slack.com/services/T000/B000/synthetic"))
	}
	return nil, fmt.Errorf("wrong purpose")
}

type notificationWorkflowTransport func(*http.Request) (*http.Response, error)

func (f notificationWorkflowTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestNotificationReadinessCompleteAcknowledgedWorkflow(t *testing.T) {
	ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "operator-a", Kind: identity.PrincipalHuman, Method: identity.LocalOSPeerMethod})
	now := time.Now().UTC().Truncate(time.Second)
	clock := time.Now
	directory, e := os.MkdirTemp("/var/tmp", "vsk323-notification-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	path := filepath.Join(directory, "control.db")
	cfg := store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "1.0.0", BuildVersion: "notification-fixture", Clock: clock}
	// A task-local overlay permits only this synthetic filesystem fixture on Mac;
	// normal unsupported-platform behavior is unchanged in committed production.
	if runtime.GOOS != "linux" {
		cfg.Filesystem = notificationWorkflowFS{}
	}
	s, e := store.Open(ctx, cfg)
	if e != nil {
		t.Fatal("open", e)
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
			t.Fatal(q, e)
		}
	}
	p := generated.NotificationReadinessPolicy{Schema: generated.SchemaIDNotificationReadinessPolicy, SchemaVersion: "1.0.0", TargetID: "notification-route", PrimaryHumanID: "operator-a", SecondaryHumanID: "secondary-human", PrimaryCredentialOwnerID: "primary-owner", SecondaryCredentialOwnerID: "secondary-owner", PrimaryCredentialClass: "fine-grained-pat", SecondaryChannelID: "synthetic-channel", PrimaryReferenceID: "github-test", PrimaryMaterialVersion: "v1", SecondaryReferenceID: "slack-test", SecondaryMaterialVersion: "v1"}
	primary := generated.OperationsGithubDestination{Schema: generated.SchemaIDOperationsGithubDestination, SchemaVersion: "1.0.0", TargetID: "ordinary-github-route", Endpoint: "https://api.example", Repository: "owner/alerts", RepositoryID: 123, ReferenceID: "ordinary-github", MaterialVersion: "v1"}
	for id, v := range map[string]any{generated.SchemaIDNotificationReadinessPolicy: p, generated.SchemaIDOperationsGithubDestination: primary} {
		raw, _ := json.Marshal(v)
		if e := generated.ValidateContractJSON(id, raw, generated.ContractExact); e != nil {
			t.Fatal("protected fixture configuration", e)
		}
	}
	repo := store.NewNotificationReadinessRepository(s, p, primary)
	for _, id := range []string{"operator-a", "secondary-human", "primary-owner", "secondary-owner"} {
		exec(`INSERT INTO effective_authorization_principals VALUES(?,'human','active',1,'now','now')`, id)
	}
	grant := func(id, action, cap, kind, target string) {
		var branch any
		if action == "execute" || action == "acknowledge" {
			branch = "human"
		}
		exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?,?,?,1,'active','now','now')`, id, action, cap, kind, target, branch)
	}
	grant("canary-execute", "execute", operations.ReadinessOperation, "execution-target", p.TargetID)
	grant("canary-ack", "acknowledge", "plan.acknowledge", "plan-target", p.TargetID)
	grant("evidence-author", "author", "gate.evidence.author", "gate", "g-011")
	grant("evidence-read", "read", "gate.read", "gate", "g-011")
	grant("evidence-execute", "execute", "gate.evidence.apply", "execution-target", "scope")
	grant("evidence-ack", "acknowledge", "plan.acknowledge", "plan-target", "scope")
	for i, ref := range []struct{ id, purpose string }{{p.PrimaryReferenceID, operations.ReadinessGithubPurpose}, {p.SecondaryReferenceID, operations.ReadinessSlackPurpose}} {
		exec(`INSERT INTO credential_reference_versions VALUES(?,?,?, ?,?,'native-systemd','v1',?,'active',1,0,?,?,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, fmt.Sprintf("version-%d", i), ref.id, operations.ReadinessAdapter, ref.purpose, p.TargetID, operations.Digest("synthetic-ciphertext"), now.Format(time.RFC3339), []byte(`["`+operations.ReadinessAdapter+`"]`), operations.Digest("fixture"))
	}
	caps, _ := json.Marshal([]string{"credential.operations.readiness", operations.ReadinessCapability(repo.Digest)})
	exec(`INSERT INTO gate_applied_profiles VALUES('fixture-profile','vegastack-labs','1.0.0','fixture-policy','1.0.0',?,1,0,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, caps, operations.Digest("fixture"))
	revisions := store.NewPlanRepository(s)
	declarations, e := change.NewService(store.NewDeclarationRepository(s), clock)
	if e != nil {
		t.Fatal(e)
	}
	observations, _ := planengine.NewStateObservationReader(revisions)
	plans, e := planengine.NewService(planengine.Config{Repository: revisions, Observations: observations, Clock: clock, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if e != nil {
		t.Fatal(e)
	}
	ackRepo := store.NewAcknowledgementRepository(s)
	ack, e := acknowledgement.NewService(acknowledgement.Config{Repository: ackRepo, Plans: notificationWorkflowPlanReader{plans}, Authorizer: authorization.NewEvaluator(store.NewEffectiveAuthorizationRepository(s)), Clock: clock})
	if e != nil {
		t.Fatal(e)
	}
	monitor := &operationsMonitoring{s: s, clock: clock, build: result.BuildInfo{ToolVersion: "1.0.0", ReleaseBuildID: "notification-fixture"}}
	n := &notificationReadiness{monitor: monitor, repo: repo, declarations: declarations, results: map[string]adapter.ExactExecutionBinding{}}
	monitor.readiness = n
	issueBody, issueState := "", ""
	githubWrites, slackWrites := 0, 0
	tr := notificationWorkflowTransport(func(r *http.Request) (*http.Response, error) {
		var reply any
		switch r.URL.Host {
		case "hooks.slack.com":
			if r.Method != "POST" {
				t.Fatal("slack method")
			}
			slackWrites++
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
		case "api.example":
			switch {
			case r.URL.Path == "/repos/owner/alerts":
				reply = map[string]any{"id": 123, "full_name": "owner/alerts"}
			case r.Method == "GET":
				issues := []any{}
				if issueBody != "" {
					issues = append(issues, map[string]any{"number": 17, "body": issueBody, "state": issueState})
				}
				reply = issues
			case r.Method == "POST" || r.Method == "PATCH":
				var v map[string]any
				if e := json.NewDecoder(r.Body).Decode(&v); e != nil {
					t.Fatal(e)
				}
				issueBody, _ = v["body"].(string)
				issueState = "open"
				if v["state"] == "closed" {
					issueState = "closed"
				}
				githubWrites++
				reply = map[string]any{"number": 17, "state": issueState}
			default:
				t.Fatal("unexpected github method")
			}
		default:
			t.Fatal("external HTTP escaped synthetic transport", r.URL.Host)
		}
		raw, _ := json.Marshal(reply)
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})
	n.github = func(b githubalerts.Borrow) (*githubalerts.Client, error) {
		return githubalerts.New(primary.Endpoint, primary.Repository, primary.RepositoryID, tr, b)
	}
	n.slack = slackalerts.NewClient(tr, clock)
	registry := adapter.NewRegistry()
	if e = registry.Register(operations.ReadinessAdapter, n); e != nil {
		t.Fatal(e)
	}
	resolver := &notificationWorkflowResolver{}
	if e = registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: operations.ReadinessAdapter, ProfileID: "vegastack-labs", CapabilityID: "credential.operations.readiness", Enabled: true}, resolver); e != nil {
		t.Fatal(e)
	}
	core, e := runengine.NewCoreGateEffect(store.NewGateRepository(s), ackRepo, "notification-fixture", "1.0.0", clock)
	if e != nil {
		t.Fatal(e)
	}
	engine, e := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(s), Plans: plans, Admission: runengine.NewAdmissionGate(ack, clock), Adapters: registry, SecretGate: notificationReadinessGate{source: n, fallback: runengine.UnavailableGateVerifier{}}, Core: runengine.CoreRouter{Gate: core}, CredentialStep: &runengine.CredentialStep{Bindings: store.NewCredentialRepository(s), Resolvers: registry, Profiles: store.NewGateRepository(s), Plans: plans, Clock: clock}, Clock: clock})
	if e != nil {
		t.Fatal(e)
	}
	apply := func(d generated.DeclarationRevision, key string) generated.Run {
		t.Helper()
		prep, e := plans.Prepare(ctx, d.DeclarationID, d.Revision)
		if e != nil {
			t.Fatal("prepare plan", e)
		}
		made, e := plans.Create(ctx, planengine.AuthorScope{PrincipalID: "operator-a", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "fixture-session"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: d.DeclarationID, DeclarationRevision: d.Revision, ExpectedStateRevision: prep.ExpectedStateRevision, RecoveryEpoch: prep.RecoveryEpoch, ObservationFingerprint: prep.ObservationFingerprint, IdempotencyKey: key + "-plan", Extensions: d.Extensions})
		if e != nil {
			t.Fatal("plan", e)
		}
		plan := made.Plan
		human := identity.Principal{ID: "operator-a", Kind: identity.PrincipalHuman, Method: identity.SlackSocketModeMethod}
		card, e := ack.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: key + "-nonce"}, plan.PlanID)
		if e != nil {
			t.Fatal("ack request", e)
		}
		expires, _ := time.Parse(time.RFC3339, card.Request.ExpiresAt)
		approved, e := ack.Decide(ctx, acknowledgement.Candidate{Human: human, AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: card.Request.TargetDigest, ReasonDigest: card.Request.ReasonDigest, Nonce: card.Nonce, StateRevision: card.Request.StateRevision, RecoveryEpoch: card.Request.RecoveryEpoch, ExpiresAt: expires, DecidedAt: now})
		if e != nil {
			t.Fatal("ack decide", e)
		}
		permission, e := authorization.NewEvaluator(store.NewEffectiveAuthorizationRepository(s)).Authorize(ctx, identity.Principal{ID: "operator-a", Kind: identity.PrincipalHuman, Method: identity.LocalOSPeerMethod}, authorization.Request{Action: authorization.ActionExecute, Target: authorization.Target{Capability: plan.Operations[0].OperationType, ResourceKind: "execution-target", ResourceID: plan.Operations[0].TargetID}, Plan: &plan, Branches: []authorization.Branch{authorization.BranchHuman}})
		if e != nil || !permission.Allowed {
			t.Fatal("actual execute authorization", permission, e)
		}
		branch := string(*permission.Branch)
		decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: key + "-decision", PrincipalID: permission.PrincipalID, Action: string(permission.Action), TargetID: permission.Target.ResourceID, Allowed: permission.Allowed, Branch: &branch, ReasonCode: permission.ReasonCode, GrantRevision: permission.GrantRevision, PlanDigest: permission.PlanDigest, DecidedAt: clock().UTC().Truncate(time.Second).Format(time.RFC3339), Extensions: []generated.ContractExtension{}}

		got, e := engine.Submit(ctx, runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RecoveryEpoch: plan.Binding.RecoveryEpoch, IdempotencyKey: key + "-run", Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: audit.Attribution{AuthenticatedPrincipalID: "operator-a", AuthenticatedPrincipalMethod: identity.LocalOSPeerMethod, ResponsibleHumanPrincipalID: &human.ID}})
		if e != nil || got.Status != "succeeded" {
			t.Fatalf("%s execute: status=%s err=%v run=%+v", key, got.Status, e, got)
		}
		return got
	}
	// Establish the seeded initial declarations' actual revision through the real inert writer.
	_, e = declarations.Revise(ctx, change.AuthorScope{PrincipalID: "operator-a", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "initial-fixture"}, generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: "initial-fixture", DeclarationType: "fixture-initial-state", ExpectedRevision: 1, ExpectedStateRevision: 0, RecoveryEpoch: 0, ReasonDigest: operations.Digest("fixture"), Extensions: []generated.ContractExtension{}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "fixture-initial-state", OperationType: "fixture.initial", AdapterID: "fixture.initial", TargetID: "fixture", InputDigest: operations.Digest("fixture"), ArtifactDigest: operations.Digest("fixture"), Idempotent: true}}})
	if e != nil {
		t.Fatal("initial fixture declaration", e)
	}
	current, _ := revisions.CurrentRevision(ctx)
	draft, e := n.prepare(ctx, generated.NotificationReadinessRequest{Schema: generated.SchemaIDNotificationReadinessRequest, SchemaVersion: "1.0.0", Action: "canary-draft", RequestID: "canary-one", ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch})
	if e != nil {
		t.Fatal("canary draft", e)
	}
	canary := apply(draft, "canary")
	receipts, e := repo.Receipts(ctx, canary.RunID, 0)
	if e != nil || len(receipts.Receipts) != 4 || githubWrites != 2 || slackWrites != 2 || resolver.calls != 2 || issueState != "closed" {
		t.Fatal("persisted provider receipts", receipts, e, githubWrites, slackWrites, resolver.calls)
	}
	scope, e := store.NewGateRepository(s).GetAppliedProfileScope(ctx)
	if e != nil {
		t.Fatal(e)
	}
	h, _ := s.Health(ctx)
	if monitor.notificationGatePassed(ctx, scope, h, clock()) {
		t.Fatal("unapplied receipts passed gate")
	}
	current, _ = revisions.CurrentRevision(ctx)
	evidence, e := n.prepare(ctx, generated.NotificationReadinessRequest{Schema: generated.SchemaIDNotificationReadinessRequest, SchemaVersion: "1.0.0", Action: "evidence-draft", RequestID: "evidence-one", RunID: canary.RunID, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch})
	if e != nil {
		t.Fatal("evidence draft", e)
	}
	apply(evidence, "evidence")
	scope, _ = store.NewGateRepository(s).GetAppliedProfileScope(ctx)
	h, _ = s.Health(ctx)
	evaluation, e := monitor.notificationEvaluation(ctx, scope, h, clock())
	if e != nil || evaluation.Outcome != "passed" {
		t.Fatal("G-011 after real evidence apply", evaluation, e)
	}
	if !monitor.notificationGatePassed(ctx, scope, h, clock()) {
		t.Fatal("production shared verifier rejected actual applied receipts")
	}
	if githubWrites != 2 || slackWrites != 2 || resolver.calls != 2 {
		t.Fatal("evidence collection/application sent extra messages")
	}
	exec(`UPDATE effective_authorization_principals SET status='revoked',grant_revision=2 WHERE principal_id='secondary-human'`)
	if monitor.notificationGatePassed(ctx, scope, h, clock()) {
		t.Fatal("revoked selected recipient retained qualification")
	}
}
