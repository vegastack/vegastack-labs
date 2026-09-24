package run

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type schedulePolicyEffectRepository struct {
	draft      store.ScheduledPolicyDraft
	activation store.ScheduleActivationRequest
	active     generated.ScheduledJobPolicy
}

func (repository *schedulePolicyEffectRepository) GetDraft(context.Context, string) (store.ScheduledPolicyDraft, error) {
	return repository.draft, nil
}
func (repository *schedulePolicyEffectRepository) Activate(_ context.Context, request store.ScheduleActivationRequest) (generated.ScheduledJobPolicy, error) {
	repository.activation = request
	repository.active = repository.draft.Policy
	return repository.active, nil
}
func (repository *schedulePolicyEffectRepository) GetActivePolicy(context.Context, string) (generated.ScheduledJobPolicy, error) {
	return repository.active, nil
}

func TestSchedulePolicyEffectConsumesExactAcknowledgedActivation(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	plan := testPlan(now)
	plan.AuthorizationBranch, plan.ExecutorMode = "human", "central"
	draftID, policyDigest := "schedule-draft-a", digest("scheduled-policy")
	plan.Extensions = []generated.ContractExtension{{Name: "x-scheduled-policy", ValueDigest: policyDigest}}
	plan.Operations = []generated.PlanOperation{{Sequence: 1, OperationID: "schedule-activation-a", OperationType: "schedule.policy.activate", AdapterID: "core.schedule", ExecutorID: "executor-central", TargetID: draftID, InputDigest: policyDigest, ArtifactDigest: policyDigest, Idempotent: false}}
	policy := generated.ScheduledJobPolicy{Enabled: true}
	repository := &schedulePolicyEffectRepository{draft: store.ScheduledPolicyDraft{DraftID: draftID, Digest: policyDigest, Policy: policy}}
	ackID := "ack-schedule-a"
	approvals := &fixedGateApproval{stored: acknowledgement.Stored{Consumed: true, Acknowledgement: generated.Acknowledgement{AcknowledgementID: ackID, PlanDigest: plan.PlanDigest, HumanID: "human-a", Status: "approved"}}}
	effect, err := NewSchedulePolicyEffect(repository, approvals)
	if err != nil {
		t.Fatal(err)
	}
	run := generated.Run{RunID: "run-schedule-a", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, AcknowledgementID: &ackID, ExecutorMode: "central", StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch}
	step := generated.RunStep{StepID: "step-schedule-a", OperationID: plan.Operations[0].OperationID, OperationType: plan.Operations[0].OperationType, AdapterID: plan.Operations[0].AdapterID, TargetID: draftID, InputDigest: policyDigest, ArtifactDigest: policyDigest, Status: "running", EffectState: "intent-recorded"}
	result, err := effect.Execute(context.Background(), ExactStepBinding{Plan: plan, Run: run, Step: step, Attribution: audit.Attribution{AuthenticatedPrincipalID: "human-a", AuthenticatedPrincipalMethod: "local-os-peer"}})
	if err != nil || adapter.ValidateEffect(result) != nil || repository.activation.PlanID != plan.PlanID || repository.activation.ApprovedByHumanID != "human-a" || repository.activation.DraftID != draftID {
		t.Fatalf("result=%#v activation=%#v err=%v", result, repository.activation, err)
	}
	verified, err := effect.Verify(context.Background(), ExactStepBinding{Plan: plan, Run: run, Step: step}, result)
	if err != nil || !verified.Verified || verified.Digest != policyDigest {
		t.Fatalf("verification=%#v err=%v", verified, err)
	}

	if repository.activation.Attribution.ResponsibleHumanPrincipalID == nil || *repository.activation.Attribution.ResponsibleHumanPrincipalID != "human-a" {
		t.Fatalf("responsible human not forwarded: %#v", repository.activation.Attribution)
	}
}
