//go:build linux

package store

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func TestAcknowledgementTerminalOutcomeSurvivesRestartAndCannotBeReplayed(t *testing.T) {
	config := testConfig(t)
	config.Clock = func() time.Time { return time.Date(2026, 9, 13, 1, 5, 0, 0, time.UTC) }
	s, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	plan := seedAcknowledgementPlan(t, s)
	repository := NewAcknowledgementRepository(s)
	request := acknowledgementTestCreate(plan)
	stored, created, err := repository.Create(context.Background(), request)
	if err != nil || !created || stored.Acknowledgement.Status != "pending" {
		t.Fatalf("create = %#v, %v, %v", stored, created, err)
	}
	outcome := stored.Acknowledgement
	outcome.Status = "approved"
	outcome.ReceivedAt = "2026-09-13T01:05:00Z"
	outcome.ProofDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	attribution := audit.Attribution{AuthenticatedPrincipalID: request.Request.HumanID, AuthenticatedPrincipalMethod: identity.SlackSocketModeMethod}
	stored, changed, err := repository.Decide(context.Background(), acknowledgement.DecisionRecord{Expected: request.Request, Outcome: outcome, DecidedAt: time.Date(2026, 9, 13, 1, 5, 0, 0, time.UTC), Attribution: attribution})
	if err != nil || !changed || stored.Acknowledgement.Status != "approved" {
		t.Fatalf("decide = %#v, %v, %v", stored, changed, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	config.Mode = OpenExisting
	reopened, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	repository = NewAcknowledgementRepository(reopened)
	stored, err = repository.Get(context.Background(), plan.PlanID)
	if err != nil || stored.Acknowledgement.ProofDigest != outcome.ProofDigest {
		t.Fatalf("restart = %#v, %v", stored, err)
	}
	if _, consumed, err := repository.Consume(context.Background(), plan.PlanID, time.Date(2026, 9, 13, 1, 6, 0, 0, time.UTC)); err != nil || !consumed {
		t.Fatalf("consume = %v, %v", consumed, err)
	}
	if _, consumed, err := repository.Consume(context.Background(), plan.PlanID, time.Date(2026, 9, 13, 1, 7, 0, 0, time.UTC)); err != nil || consumed {
		t.Fatalf("replay consume = %v, %v", consumed, err)
	}
	if _, err := reopened.conn.ExecContext(context.Background(), `UPDATE acknowledgement_proofs SET status='rejected'`); err == nil {
		t.Fatal("terminal proof was mutable")
	}
	if _, err := reopened.conn.ExecContext(context.Background(), `DELETE FROM acknowledgement_requests`); err == nil {
		t.Fatal("acknowledgement history was deletable")
	}
}

func seedAcknowledgementPlan(t *testing.T, s *Store) generated.Plan {
	t.Helper()
	declaration, err := NewDeclarationRepository(s).CreateRevision(context.Background(), validDeclarationStoreRequest())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewPlanRepository(s).CommitDeclarationAndPlan(context.Background(), validPlanStoreRequest(declaration.Document))
	if err != nil {
		t.Fatal(err)
	}
	return plan.Plan
}

func acknowledgementTestCreate(plan generated.Plan) acknowledgement.CreateRecord {
	request := generated.AcknowledgementRequest{Schema: generated.SchemaIDAcknowledgementRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, HumanID: "person-operator", AuthorityID: "authority-slack", NonceDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, ExpiresAt: plan.ExpiresAt, Extensions: []generated.ContractExtension{}}
	pending := generated.Acknowledgement{Schema: generated.SchemaIDAcknowledgement, SchemaVersion: "1.0.0", PlanID: request.PlanID, PlanDigest: request.PlanDigest, TargetDigest: request.TargetDigest, ReasonDigest: request.ReasonDigest, HumanID: request.HumanID, AuthorityID: request.AuthorityID, NonceDigest: request.NonceDigest, StateRevision: request.StateRevision, RecoveryEpoch: request.RecoveryEpoch, ExpiresAt: request.ExpiresAt, AcknowledgementID: "ack-test", ProofDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", Status: "pending", ReceivedAt: "2026-09-13T01:05:00Z", Extensions: []generated.ContractExtension{}}
	attribution := audit.Attribution{AuthenticatedPrincipalID: request.HumanID, AuthenticatedPrincipalMethod: identity.SlackSocketModeMethod}
	return acknowledgement.CreateRecord{Request: request, Pending: pending, CreatedAt: time.Date(2026, 9, 13, 1, 5, 0, 0, time.UTC), Attribution: attribution}
}
