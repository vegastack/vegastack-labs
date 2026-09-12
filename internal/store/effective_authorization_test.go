//go:build linux

package store

import (
	"context"
	"embed"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

//go:embed pending-migrations/0007_effective_authorization.sql
var pendingEffectiveAuthorizationMigration embed.FS

func TestDesiredGrantCannotAuthorizeItselfAndRevocationIsImmediate(t *testing.T) {
	store := openEffectiveAuthorizationStore(t)
	defer store.Close()
	repository := NewEffectiveAuthorizationRepository(store)
	evaluator := authorization.NewEvaluator(repository)
	plan := authorizationTestPlan(authorization.BranchHuman)
	target := authorization.Target{Capability: "application.deploy", ResourceKind: "application", ResourceID: "app-test"}
	request := authorization.Request{Action: authorization.ActionExecute, Target: target, Plan: &plan, Branches: []authorization.Branch{authorization.BranchHuman}}

	seedEffectivePrincipal(t, store, "human-operator", identity.PrincipalHuman, 1)
	seedEffectiveGrant(t, store, "grant-operator", "human-operator", authorization.RoleMaintainer, authorization.ActionExecute, target, authorization.BranchHuman, 1)
	decision, err := evaluator.Authorize(context.Background(), identity.Principal{ID: "human-operator", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}, request)
	if err != nil || !decision.Allowed {
		t.Fatalf("initial authorization = %#v, %v", decision, err)
	}

	seedDesiredGrant(t, store, "desired-self", "policy-agent", "policy-agent", authorization.RolePreauthorizedExecutor, authorization.ActionExecute, target, authorization.BranchPreauthorized, 1)
	policyPlan := authorizationTestPlan(authorization.BranchPreauthorized)
	request.Plan = &policyPlan
	request.Branches = []authorization.Branch{authorization.BranchPreauthorized}
	decision, err = evaluator.Authorize(context.Background(), identity.Principal{ID: "policy-agent", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalPolicy}, request)
	if err != nil || decision.Allowed {
		t.Fatalf("desired self-grant authorized = %#v, %v", decision, err)
	}

	if _, err := store.conn.ExecContext(context.Background(), `UPDATE effective_authorization_grants SET status='revoked',grant_revision=2,updated_at=? WHERE grant_id='grant-operator'`, testAuthorizationTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.conn.ExecContext(context.Background(), `UPDATE effective_authorization_principals SET grant_revision=2,updated_at=? WHERE principal_id='human-operator'`, testAuthorizationTime()); err != nil {
		t.Fatal(err)
	}
	request.Plan = &plan
	request.Branches = []authorization.Branch{authorization.BranchHuman}
	decision, err = evaluator.Authorize(context.Background(), identity.Principal{ID: "human-operator", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}, request)
	if err != nil || decision.Allowed {
		t.Fatalf("revoked grant authorized = %#v, %v", decision, err)
	}
}

func TestEffectivePolicySnapshotSurvivesRestartAndBindsCurrentRevisions(t *testing.T) {
	config := testConfig(t)
	store, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	installPendingEffectiveAuthorizationMigration(t, store)
	target := authorization.Target{Capability: "declaration.author", ResourceKind: "project", ResourceID: "project-test"}
	seedEffectivePrincipal(t, store, "human-author", identity.PrincipalHuman, 3)
	seedEffectiveGrant(t, store, "grant-author", "human-author", authorization.RoleAuthor, authorization.ActionAuthor, target, "", 3)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	config.Mode = OpenExisting
	store, err = Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot, err := NewEffectiveAuthorizationRepository(store).Snapshot(context.Background(), "human-author", target)
	if err != nil || snapshot.GrantRevision != 3 || snapshot.RecoveryEpoch != 0 || len(snapshot.Grants) != 1 {
		t.Fatalf("snapshot after restart = %#v, %v", snapshot, err)
	}

	evaluator := authorization.NewEvaluator(NewEffectiveAuthorizationRepository(store))
	decision, err := evaluator.Authorize(context.Background(), identity.Principal{ID: "human-author", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}, authorization.Request{Action: authorization.ActionAuthor, Target: target, ExpectedGrantRevision: 2})
	if err != nil || decision.Allowed || decision.ReasonCode != authorization.ReasonGrantRevisionStale {
		t.Fatalf("stale grant decision = %#v, %v", decision, err)
	}
	decision, err = evaluator.Authorize(context.Background(), identity.Principal{ID: "human-author", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}, authorization.Request{Action: authorization.ActionAuthor, Target: target, ExpectedRecoveryEpoch: 9})
	if err != nil || decision.Allowed || decision.ReasonCode != authorization.ReasonRecoveryEpochMismatch {
		t.Fatalf("recovery mismatch decision = %#v, %v", decision, err)
	}
}

func TestRecordDecisionIsAppendOnlySanitizedAndIdempotent(t *testing.T) {
	store := openEffectiveAuthorizationStore(t)
	defer store.Close()
	repository := NewEffectiveAuthorizationRepository(store)
	target := authorization.Target{Capability: "application.deploy", ResourceKind: "application", ResourceID: "app-test"}
	decision := authorization.Decision{PrincipalID: "human-operator", Action: authorization.ActionExecute, Target: target, Allowed: false, ReasonCode: authorization.ReasonGrantMissing, GrantRevision: 2, StateRevision: 0, RecoveryEpoch: 0, PlanDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	attribution, err := audit.NewAttribution(identity.Principal{ID: "human-operator", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	record := authorization.DecisionRecord{
		DecisionID: "decision-test", Decision: decision, DecidedAt: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC), CorrelationID: "authorization-test", Attribution: attribution,
		Idempotency: audit.IntentKey{Scope: "authorization-decision", KeyDigest: testAuthorizationDigest("key"), RequestDigest: testAuthorizationDigest("request")},
	}
	if err := repository.RecordDecision(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if err := repository.RecordDecision(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	var decisions, events, intents int
	for table, destination := range map[string]*int{"authorization_decisions": &decisions, "audit_events": &events, "intent_keys": &intents} {
		if err := store.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(destination); err != nil {
			t.Fatal(err)
		}
	}
	if decisions != 1 || events != 1 || intents != 1 {
		t.Fatalf("counts decisions=%d events=%d intents=%d", decisions, events, intents)
	}
	var reason, planDigest string
	if err := store.conn.QueryRowContext(context.Background(), `SELECT reason_code,plan_digest FROM authorization_decisions WHERE decision_id='decision-test'`).Scan(&reason, &planDigest); err != nil {
		t.Fatal(err)
	}
	if reason != authorization.ReasonGrantMissing || planDigest != decision.PlanDigest {
		t.Fatalf("stored decision reason=%q plan=%q", reason, planDigest)
	}
	if _, err := store.conn.ExecContext(context.Background(), `UPDATE authorization_decisions SET reason_code='allowed' WHERE decision_id='decision-test'`); err == nil {
		t.Fatal("append-only decision was updated")
	}
}

func TestStageDesiredGrantRequiresPriorEffectiveAuthorScope(t *testing.T) {
	store := openEffectiveAuthorizationStore(t)
	defer store.Close()
	repository := NewEffectiveAuthorizationRepository(store)
	policyTarget := authorization.Target{Capability: "authorization.policy.write", ResourceKind: "authorization-policy", ResourceID: "policy-agent"}
	seedEffectivePrincipal(t, store, "human-admin", identity.PrincipalHuman, 5)
	seedEffectiveGrant(t, store, "grant-policy-author", "human-admin", authorization.RoleControlPlaneAdmin, authorization.ActionAuthor, policyTarget, "", 5)
	decision, err := authorization.NewEvaluator(repository).Authorize(context.Background(), identity.Principal{ID: "human-admin", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}, authorization.Request{Action: authorization.ActionAuthor, Target: policyTarget})
	if err != nil || !decision.Allowed {
		t.Fatalf("policy author scope = %#v, %v", decision, err)
	}
	attribution, err := audit.NewAttribution(identity.Principal{ID: "human-admin", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := PolicyChangeRequest{
		Expected: RevisionToken{}, AuthorScope: decision.Scope, CorrelationID: "policy-change-test", Attribution: attribution,
		Idempotency: audit.IntentKey{Scope: "policy-change", KeyDigest: testAuthorizationDigest("key"), RequestDigest: testAuthorizationDigest("request")},
		Grant:       DesiredAuthorizationGrant{ID: "desired-policy-agent", PrincipalID: "policy-agent", Role: authorization.RolePreauthorizedExecutor, Action: authorization.ActionExecute, Target: authorization.Target{Capability: "application.deploy", ResourceKind: "application", ResourceID: "app-test"}, Branch: authorization.BranchPreauthorized, DesiredRevision: 1, CreatedAt: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)},
	}
	commit, err := repository.StageDesiredGrant(context.Background(), request)
	if err != nil || !commit.Changed || commit.StateRevision != 1 {
		t.Fatalf("stage desired grant = %#v, %v", commit, err)
	}
	var desired, effective int
	if err := store.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM desired_authorization_grants WHERE desired_grant_id='desired-policy-agent'`).Scan(&desired); err != nil {
		t.Fatal(err)
	}
	if err := store.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM effective_authorization_grants WHERE principal_id='policy-agent'`).Scan(&effective); err != nil {
		t.Fatal(err)
	}
	if desired != 1 || effective != 0 {
		t.Fatalf("desired=%d effective=%d", desired, effective)
	}

	fresh, err := authorization.NewEvaluator(repository).Authorize(context.Background(), identity.Principal{ID: "human-admin", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}, authorization.Request{Action: authorization.ActionAuthor, Target: policyTarget})
	if err != nil || !fresh.Allowed {
		t.Fatalf("fresh policy author scope = %#v, %v", fresh, err)
	}
	request.Expected = RevisionToken{StateRevision: 1, RecoveryEpoch: 0}
	request.AuthorScope = fresh.Scope
	request.Grant.ID = "desired-forged"
	request.AuthorScope.ScopeDigest = string(testAuthorizationDigest("request"))
	request.Idempotency.KeyDigest = testAuthorizationDigest("request")
	request.Idempotency.RequestDigest = testAuthorizationDigest("key")
	if _, err := repository.StageDesiredGrant(context.Background(), request); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("forged scope code = %q, err = %v", Code(err), err)
	}
}

func openEffectiveAuthorizationStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(context.Background(), testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	installPendingEffectiveAuthorizationMigration(t, store)
	return store
}

func installPendingEffectiveAuthorizationMigration(t *testing.T, store *Store) {
	t.Helper()
	body, err := pendingEffectiveAuthorizationMigration.ReadFile("pending-migrations/0007_effective_authorization.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.conn.ExecContext(context.Background(), string(body)); err != nil {
		t.Fatal(err)
	}
}

func seedEffectivePrincipal(t *testing.T, store *Store, principalID string, kind identity.PrincipalKind, revision int64) {
	t.Helper()
	now := testAuthorizationTime()
	if _, err := store.conn.ExecContext(context.Background(), `INSERT INTO effective_authorization_principals(principal_id,principal_kind,status,grant_revision,created_at,updated_at) VALUES(?,?,'active',?,?,?)`, principalID, kind, revision, now, now); err != nil {
		t.Fatal(err)
	}
}

func seedEffectiveGrant(t *testing.T, store *Store, grantID, principalID string, role authorization.Role, action authorization.Action, target authorization.Target, branch authorization.Branch, revision int64) {
	t.Helper()
	now := testAuthorizationTime()
	var branchValue any
	if branch != "" {
		branchValue = branch
	}
	if _, err := store.conn.ExecContext(context.Background(), `INSERT INTO effective_authorization_grants(grant_id,principal_id,role_id,action,capability,resource_kind,resource_id,branch,grant_revision,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,'active',?,?)`, grantID, principalID, role, action, target.Capability, target.ResourceKind, target.ResourceID, branchValue, revision, now, now); err != nil {
		t.Fatal(err)
	}
}

func seedDesiredGrant(t *testing.T, store *Store, grantID, principalID, proposedBy string, role authorization.Role, action authorization.Action, target authorization.Target, branch authorization.Branch, revision int64) {
	t.Helper()
	now := testAuthorizationTime()
	if _, err := store.conn.ExecContext(context.Background(), `INSERT INTO desired_authorization_grants(desired_grant_id,principal_id,proposed_by_principal_id,role_id,action,capability,resource_kind,resource_id,branch,desired_revision,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,'draft',?)`, grantID, principalID, proposedBy, role, action, target.Capability, target.ResourceKind, target.ResourceID, branch, revision, now); err != nil {
		t.Fatal(err)
	}
}

func authorizationTestPlan(branch authorization.Branch) generated.Plan {
	return generated.Plan{PlanID: "plan-test", PlanDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Risk: string(authorization.RiskRoutine), AuthorizationBranch: string(branch), Binding: generated.PlanBinding{StateRevision: 0, RecoveryEpoch: 0}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: "operation-test", OperationType: "application.deploy.low-risk", TargetID: "app-test"}}}
}

func testAuthorizationTime() string { return "2026-09-13T00:00:00Z" }

func testAuthorizationDigest(seed string) audit.Fingerprint {
	return audit.Fingerprint("sha256:" + map[string]string{"key": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "request": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}[seed])
}
