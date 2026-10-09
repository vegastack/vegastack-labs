package store

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func TestHostActionExecutionCannotUseMissingAuthority(t *testing.T) {
	r := NewHostActionRepository(nil)
	if _, err := r.CurrentExecution(context.Background(), adapter.Operation{}, adapter.ExactExecutionBinding{}); err == nil {
		t.Fatal("missing current authority accepted")
	}
}

func actionDraftFixture(t *testing.T) (*registrationStoreFixture, *HostActionRepository, generated.HostActionRequest) {
	t.Helper()
	f := newRegistrationStoreFixture(t)
	d := f.Stage(t)
	b := f.bind(t, d)
	if _, err := f.repo.Apply(f.ctx, b); err != nil {
		t.Fatal(err)
	}
	revision, err := NewPlanRepository(f.s).CurrentRevision(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.conn.ExecContext(f.ctx, `INSERT INTO effective_authorization_grants VALUES('action-prepare','operator-a','infrastructure-admin','author','host.action.prepare','host','synthetic-host',NULL,1,'active','now','now')`); err != nil {
		t.Fatal(err)
	}
	c := f.request.Confirmation
	req := generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", ActionID: "test.write-file", ActionVersion: "1.0.0", ActionInput: "{}", ActionInputDigest: hostaction.BytesDigest([]byte("{}")), HostID: f.request.HostID, TargetRevision: c.TargetRevision, TargetDigest: c.TargetDigest, AutomationPrincipalID: "automation-a", CallerUID: 1001, CredentialReferenceID: "reference-a", CredentialMaterialVersion: "version-a", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: c.TargetDigest, HostIdentityDigest: c.IdentityDigest}, ExpectedStateRevision: revision.StateRevision, RecoveryEpoch: revision.RecoveryEpoch, IdempotencyKey: "action-draft-a"}
	return f, NewHostActionRepository(f.s), req
}
func TestHostActionDraftPersistedAndInert(t *testing.T) {
	f, r, req := actionDraftFixture(t)
	d, err := r.StageDraft(f.ctx, req, f.attr)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := r.GetDraft(f.ctx, d.ID)
	if err != nil || loaded != d {
		t.Fatalf("persisted draft: %v", err)
	}
	again, err := r.StageDraft(f.ctx, req, f.attr)
	if err != nil || again != d {
		t.Fatalf("idempotent draft: %v", err)
	}
	var count int
	if err := f.s.conn.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM plan_runs WHERE plan_id=?`, d.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("draft initiated execution")
	}
	c := generated.HostActionCredentialConfirmation{Method: req.ConsoleConfirmation.Method, HostIdentityDigest: req.ConsoleConfirmation.HostIdentityDigest, TargetDigest: req.TargetDigest, TargetRevision: req.TargetRevision}
	if err := r.VerifyHostActionConsole(f.ctx, req.HostID, c, req.RecoveryEpoch); err != nil {
		t.Fatal(err)
	}
	c.TargetRevision++
	if err := r.VerifyHostActionConsole(f.ctx, req.HostID, c, req.RecoveryEpoch); err == nil {
		t.Fatal("stale console attestation accepted")
	}
}
func TestHostActionDraftDenialsAreAudited(t *testing.T) {
	f, r, req := actionDraftFixture(t)
	if _, err := f.s.conn.ExecContext(f.ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='action-prepare'`); err != nil {
		t.Fatal(err)
	}
	if _, err := r.StageDraft(f.ctx, req, f.attr); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("revoked author: %v", err)
	}
	var n int
	if err := f.s.conn.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM audit_events WHERE event_type='host.action.prepare-denied'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("missing denial audit: %v count%d", err, n)
	}
}
