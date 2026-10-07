package run

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
)

func TestDiscoveryTargetEffectRejectsMissingBinding(t *testing.T) {
	effect := &HostDiscoveryTargetEffect{}
	if _, err := effect.Execute(context.Background(), ExactStepBinding{}); err == nil {
		t.Fatal("unbound execution allowed")
	}
	if _, err := effect.Verify(context.Background(), ExactStepBinding{}, adapter.Effect{}); err == nil {
		t.Fatal("unbound verification allowed")
	}
}

type discoveryEffectSpy struct {
	DiscoveryTargetRepository
	calls int
}

func (r *discoveryEffectSpy) GetDraft(context.Context, string) (store.DiscoveryDraft, error) {
	r.calls++
	return store.DiscoveryDraft{}, nil
}
func TestDiscoveryTargetRequiresRecoveryPrecheckBeforeDraftAccess(t *testing.T) {
	repo := &discoveryEffectSpy{}
	approval := &fixedGateApproval{}
	effect := &HostDiscoveryTargetEffect{Repository: repo, Approvals: approval, RecoveryPrecheck: UnavailableGateVerifier{}}
	binding := ExactStepBinding{Plan: generated.Plan{PlanID: "plan-a", PlanDigest: "digest-a", AuthorizationBranch: "human", ExecutorMode: "central", Operations: []generated.PlanOperation{{AdapterID: "core.host-discovery-target"}}}, Run: generated.Run{RunID: "run-a", AcknowledgementID: new("ack-a")}, Step: generated.RunStep{StepID: "step-a", AdapterID: "core.host-discovery-target", EffectState: "intent-recorded"}, Lease: generated.ExecutorLease{Status: "active", RunID: "run-a", StepID: "step-a", PlanID: "plan-a", PlanDigest: "digest-a"}}
	if _, err := effect.Execute(context.Background(), binding); Code(err) != generated.ErrorCodePrerequisiteBlocked || repo.calls != 0 || approval.calls != 0 {
		t.Fatalf("unqualified recovery accepted: %v", err)
	}
}
