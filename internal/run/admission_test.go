package run

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestAdmissionGateBindsCurrentHumanProofAndDeniesExpiredOrMissingProof(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	plan := testPlan(now)
	plan.AuthorizationBranch = "human"
	branch := "human"
	decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-human-test", PrincipalID: "human-test", Action: "execute", TargetID: plan.Operations[0].TargetID, Allowed: true, Branch: &branch, ReasonCode: "allowed", GrantRevision: 2, RecoveryEpoch: plan.Binding.RecoveryEpoch, PlanDigest: plan.PlanDigest, DecidedAt: now.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	acknowledgement := generated.Acknowledgement{Schema: generated.SchemaIDAcknowledgement, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, HumanID: "human-test", AuthorityID: "authority-test", NonceDigest: digest("ack-nonce"), StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339), AcknowledgementID: "ack-human-test", ProofDigest: digest("ack-proof"), Status: "approved", ReceivedAt: now.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	gate := NewAdmissionGate(fixedAcknowledgementSource{value: acknowledgement}, func() time.Time { return now })
	if err := gate.Verify(context.Background(), plan, decision, &acknowledgement); err != nil {
		t.Fatal(err)
	}
	run := generated.Run{PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, AuthorizationDecisionID: decision.DecisionID, AcknowledgementID: &acknowledgement.AcknowledgementID, PolicyVersion: plan.Binding.PolicyVersion, RecoveryEpoch: plan.Binding.RecoveryEpoch, CreatedAt: now.Format(time.RFC3339)}
	if err := gate.VerifyRun(context.Background(), plan, run); err != nil {
		t.Fatal(err)
	}
	expired := acknowledgement
	expired.ExpiresAt = now.Format(time.RFC3339)
	if Code(gate.Verify(context.Background(), plan, decision, &expired)) != generated.ErrorCodeApprovalRequired {
		t.Fatal("expired acknowledgement did not fail closed")
	}
	if Code(NewAdmissionGate(nil, func() time.Time { return now }).VerifyRun(context.Background(), plan, run)) != generated.ErrorCodeApprovalRequired {
		t.Fatal("resume without durable acknowledgement source did not fail closed")
	}
}

type fixedAcknowledgementSource struct{ value generated.Acknowledgement }

func (source fixedAcknowledgementSource) GetAcknowledgement(context.Context, string) (generated.Acknowledgement, error) {
	return source.value, nil
}
