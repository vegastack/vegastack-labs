package acknowledgement

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestRejectedPlanCannotBeRequestedAgain(t *testing.T) {
	service, repository, plan := newService(t)
	card, err := service.Request(context.Background(), requestScope(), plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	candidate := candidateFor(card, plan, "rejected")
	if _, err := service.Decide(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Request(context.Background(), requestScope(), plan.PlanID); errorCode(err) != generated.ErrorCodePlanStale {
		t.Fatalf("second request code = %q, err = %v", errorCode(err), err)
	}
	if repository.created != 1 || repository.decided != 1 {
		t.Fatalf("writes = create %d, decide %d", repository.created, repository.decided)
	}
}

func TestDecisionRequiresExactBindingsAndProofIsSingleUse(t *testing.T) {
	service, repository, plan := newService(t)
	card, err := service.Request(context.Background(), requestScope(), plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	valid := candidateFor(card, plan, "approved")
	mutations := []struct {
		code   string
		mutate func(*Candidate)
	}{
		{generated.ErrorCodeAuthorizationDenied, func(value *Candidate) { value.Human.ID = "person-wrong" }},
		{generated.ErrorCodeAuthorizationDenied, func(value *Candidate) { value.AuthorityID = "authority-wrong" }},
		{generated.ErrorCodeAuthorizationDenied, func(value *Candidate) {
			value.PlanDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}},
		{generated.ErrorCodeAuthorizationDenied, func(value *Candidate) {
			value.TargetDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}},
		{generated.ErrorCodeAuthorizationDenied, func(value *Candidate) {
			value.ReasonDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}},
		{generated.ErrorCodeAuthorizationDenied, func(value *Candidate) { value.Nonce = "nonce-wrong" }},
		{generated.ErrorCodePlanStale, func(value *Candidate) { value.StateRevision++ }},
		{generated.ErrorCodeRecoveryEpochMismatch, func(value *Candidate) { value.RecoveryEpoch++ }},
		{generated.ErrorCodeAuthorizationDenied, func(value *Candidate) { value.ExpiresAt = value.ExpiresAt.Add(time.Minute) }},
		{generated.ErrorCodeAuthorizationDenied, func(value *Candidate) { value.Action = "widen" }},
	}
	for index, test := range mutations {
		candidate := valid
		test.mutate(&candidate)
		if _, err := service.Decide(context.Background(), candidate); errorCode(err) != test.code {
			t.Fatalf("mutation %d code = %q, err = %v", index, errorCode(err), err)
		}
	}
	approved, err := service.Decide(context.Background(), valid)
	if err != nil || approved.Status != "approved" {
		t.Fatalf("approve = %#v, %v", approved, err)
	}
	delayedDuplicate := valid
	delayedDuplicate.DecidedAt = delayedDuplicate.DecidedAt.Add(2 * time.Second)
	service.config.Clock = func() time.Time { return time.Date(2026, 9, 13, 1, 5, 2, 0, time.UTC) }
	duplicate, err := service.Decide(context.Background(), delayedDuplicate)
	if err != nil || duplicate.ProofDigest != approved.ProofDigest || repository.decided != 1 {
		t.Fatalf("duplicate = %#v, %v; writes %d", duplicate, err, repository.decided)
	}
	if _, err := service.VerifyForExecution(context.Background(), plan.PlanID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.VerifyForExecution(context.Background(), plan.PlanID); errorCode(err) != generated.ErrorCodePlanStale {
		t.Fatalf("replay code = %q, err = %v", errorCode(err), err)
	}
	if repository.denied == 0 {
		t.Fatal("replayed proof denial was not audited")
	}
}

func TestAgentCredentialsCannotForgeOrReplaySlackApproval(t *testing.T) {
	service, _, plan := newService(t)
	card, err := service.Request(context.Background(), requestScope(), plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	valid := candidateFor(card, plan, ActionApprove)
	hostile := []Candidate{valid, valid, valid, valid, valid}
	hostile[0].Human = identity.Principal{ID: "agent-local", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalAgent}
	hostile[1].Nonce = "replayed-or-guessed-nonce"
	hostile[2].PlanDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hostile[3].StateRevision++
	hostile[4].RecoveryEpoch++
	for index, candidate := range hostile {
		if _, err := service.Decide(context.Background(), candidate); err == nil {
			t.Fatalf("hostile candidate %d accepted", index)
		}
	}
	if _, err := service.VerifyForExecution(context.Background(), plan.PlanID); err == nil {
		t.Fatal("hostile candidates created executable approval")
	}
	if _, err := service.Decide(context.Background(), valid); err != nil {
		t.Fatal(err)
	}
	if _, err := service.VerifyForExecution(context.Background(), plan.PlanID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.VerifyForExecution(context.Background(), plan.PlanID); errorCode(err) != generated.ErrorCodePlanStale {
		t.Fatalf("replay code = %q, err = %v", errorCode(err), err)
	}
}

func TestDecisionReauthorizesHumanAndRejectsExpiredOrChangedEpoch(t *testing.T) {
	service, repository, plan := newService(t)
	card, err := service.Request(context.Background(), requestScope(), plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	service.config.Clock = func() time.Time { return time.Date(2026, 9, 13, 1, 31, 0, 0, time.UTC) }
	if _, err := service.Decide(context.Background(), candidateFor(card, plan, "approved")); errorCode(err) != generated.ErrorCodePlanStale {
		t.Fatalf("expired code = %q, err = %v", errorCode(err), err)
	}
	status, err := service.Status(context.Background(), plan.PlanID)
	if err != nil || status.Status != "expired" || repository.decided != 1 {
		t.Fatalf("expired status = %#v, %v; writes %d", status, err, repository.decided)
	}
	revokedService, _, revokedPlan := newService(t)
	revokedCard, err := revokedService.Request(context.Background(), requestScope(), revokedPlan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	revokedService.config.Authorizer = denyAuthorizer{}
	if _, err := revokedService.Decide(context.Background(), candidateFor(revokedCard, revokedPlan, "approved")); errorCode(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("revoked code = %q, err = %v", errorCode(err), err)
	}
}

func requestScope() Scope {
	return Scope{Human: identity.Principal{ID: "person-operator", Method: "slack-socket-mode", Kind: identity.PrincipalHuman}, AuthorityID: "authority-slack", Nonce: "nonce-one-time"}
}

func candidateFor(card RequestCard, plan generated.Plan, action string) Candidate {
	return Candidate{Human: requestScope().Human, AuthorityID: requestScope().AuthorityID, Action: action, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, Nonce: card.Nonce, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, ExpiresAt: mustTime(plan.ExpiresAt), DecidedAt: time.Date(2026, 9, 13, 1, 5, 0, 0, time.UTC)}
}

func newService(t *testing.T) (*Service, *memoryRepository, generated.Plan) {
	t.Helper()
	plan := generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", PlanID: "plan-test", PlanDigest: testDigest, DeclarationID: "declaration-test", Binding: generated.PlanBinding{RecoveryEpoch: 3, PriorStateRevision: 40, StateRevision: 41, DeclarationRevision: 2, ObservationFingerprint: testDigest, TargetDigest: testDigest, ReasonDigest: testDigest, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0"}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: "operation-test", OperationType: "configuration.update", AdapterID: "adapter-test", ExecutorID: "executor-central", TargetID: "target-test", InputDigest: testDigest, ArtifactDigest: testDigest, Idempotent: true}}, Status: "planned", Risk: "routine", AuthorizationBranch: "human", ExecutorMode: "central", CreatedAt: "2026-09-13T01:00:00Z", ExpiresAt: "2026-09-13T01:30:00Z", ReadableDigest: testDigest, Extensions: []generated.ContractExtension{}}
	repository := &memoryRepository{}
	service, err := NewService(Config{Repository: repository, Plans: fixedPlanReader{plan: plan}, Authorizer: allowAuthorizer{}, Clock: func() time.Time { return time.Date(2026, 9, 13, 1, 5, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	return service, repository, plan
}

type fixedPlanReader struct{ plan generated.Plan }

func (reader fixedPlanReader) Get(context.Context, string) (generated.Plan, error) {
	return reader.plan, nil
}
func (reader fixedPlanReader) ValidateCurrent(context.Context, generated.Plan) error { return nil }

type allowAuthorizer struct{}

func (allowAuthorizer) Authorize(_ context.Context, principal identity.Principal, request authorization.Request) (authorization.Decision, error) {
	branch := authorization.BranchHuman
	return authorization.Decision{PrincipalID: principal.ID, Action: request.Action, Target: request.Target, Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 7, StateRevision: request.Plan.Binding.StateRevision, RecoveryEpoch: request.Plan.Binding.RecoveryEpoch, PlanDigest: request.Plan.PlanDigest, Scope: authorization.EffectiveScope{PrincipalID: principal.ID, Action: request.Action, Capability: request.Target.Capability, ResourceKind: request.Target.ResourceKind, ResourceID: request.Target.ResourceID, Role: authorization.RoleMaintainer, GrantRevision: 7, StateRevision: request.Plan.Binding.StateRevision, RecoveryEpoch: request.Plan.Binding.RecoveryEpoch, ScopeDigest: testDigest}}, nil
}

type denyAuthorizer struct{}

func (denyAuthorizer) Authorize(_ context.Context, principal identity.Principal, request authorization.Request) (authorization.Decision, error) {
	return authorization.Decision{PrincipalID: principal.ID, Action: request.Action, Target: request.Target, ReasonCode: authorization.ReasonGrantMissing}, nil
}

type memoryRepository struct {
	stored  Stored
	created int
	decided int
	denied  int
}

func (repository *memoryRepository) Create(_ context.Context, record CreateRecord) (Stored, bool, error) {
	if repository.stored.Request.PlanID != "" {
		return repository.stored, false, nil
	}
	repository.created++
	repository.stored = Stored{Request: record.Request, Acknowledgement: record.Pending}
	return repository.stored, true, nil
}

func (repository *memoryRepository) Get(_ context.Context, _ string) (Stored, error) {
	return repository.stored, nil
}

func (repository *memoryRepository) Decide(_ context.Context, record DecisionRecord) (Stored, bool, error) {
	if repository.stored.Acknowledgement.Status != "pending" {
		return repository.stored, false, nil
	}
	repository.decided++
	repository.stored.Acknowledgement = record.Outcome
	return repository.stored, true, nil
}

func (repository *memoryRepository) Consume(_ context.Context, _ string, _ time.Time) (Stored, bool, error) {
	if repository.stored.Consumed {
		return repository.stored, false, nil
	}
	repository.stored.Consumed = true
	return repository.stored, true, nil
}

func (repository *memoryRepository) RecordDenial(context.Context, DenialRecord) error {
	repository.denied++
	return nil
}
