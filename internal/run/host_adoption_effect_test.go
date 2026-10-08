package run

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
)

type adoptionEffectRepo struct {
	draft store.HostAdoptionDraft
	calls int
}

func (r *adoptionEffectRepo) GetDraft(context.Context, string) (store.HostAdoptionDraft, error) {
	return r.draft, nil
}
func (r *adoptionEffectRepo) Apply(context.Context, store.HostAdoptionApply) (generated.ManagedHost, error) {
	r.calls++
	return generated.ManagedHost{}, nil
}
func (r *adoptionEffectRepo) Verify(context.Context, string, string, string) error { return nil }
func TestHostAdoptionEffectBinding(t *testing.T) {
	for _, mode := range []string{"valid", "missing-ack", "unconsumed", "wrong-human", "lease", "digest", "embedded", "unknown-operation"} {
		t.Run(mode, func(t *testing.T) {
			req := generated.HostAdoptionRequest{HostID: "host-a"}
			digest := hostadoption.Digest(req)
			repo := &adoptionEffectRepo{draft: store.HostAdoptionDraft{ID: "draft-a", Digest: digest, Request: req}}
			ack := "ack-a"
			approval := &fixedGateApproval{stored: acknowledgement.Stored{Consumed: true, Acknowledgement: generated.Acknowledgement{AcknowledgementID: ack, Status: "approved", PlanDigest: digest, HumanID: "human-a"}}}
			b := ExactStepBinding{Attribution: audit.Attribution{AuthenticatedPrincipalID: "operator-a", AuthenticatedPrincipalMethod: "local-os-peer"}, Plan: generated.Plan{PlanID: "plan-a", PlanDigest: digest, AuthorizationBranch: "human", ExecutorMode: "central", HostAdoption: &req, Operations: []generated.PlanOperation{{OperationType: "host.adopt"}}}, Run: generated.Run{RunID: "run-a", AcknowledgementID: &ack}, Step: generated.RunStep{StepID: "step-a", TargetID: "draft-a", AdapterID: "core.host-adoption", OperationType: "host.adopt", InputDigest: digest, ArtifactDigest: digest, EffectState: "intent-recorded"}, Lease: generated.ExecutorLease{Status: "active", PlanID: "plan-a", PlanDigest: digest, RunID: "run-a", StepID: "step-a"}}
			switch mode {
			case "missing-ack":
				b.Run.AcknowledgementID = nil
			case "unconsumed":
				approval.stored.Consumed = false
			case "wrong-human":
				approval.stored.Acknowledgement.HumanID = ""
			case "lease":
				b.Lease.RunID = "other"
			case "digest":
				b.Step.InputDigest = "wrong"
			case "embedded":
				b.Plan.HostAdoption = &generated.HostAdoptionRequest{HostID: "different"}
			case "unknown-operation":
				b.Step.OperationType = "host.anything"
			}
			e := &HostAdoptionEffect{Repository: repo, Approvals: approval}
			result, err := e.Execute(context.Background(), b)
			if mode == "valid" {
				if err != nil || repo.calls != 1 {
					t.Fatal(err)
				}
				if _, err := e.Verify(context.Background(), b, result); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || repo.calls != 0 {
				t.Fatal("invalid binding reached apply")
			}
		})
	}
	if _, err := (&HostAdoptionEffect{}).Verify(context.Background(), ExactStepBinding{}, adapter.Effect{}); err == nil {
		t.Fatal("invalid verification allowed")
	}
}
