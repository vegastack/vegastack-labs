//go:build linux

package recovery

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapters/slack"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type transferApprovalPlans struct{ repository *store.PlanRepository }

func (p transferApprovalPlans) Get(ctx context.Context, id string) (generated.Plan, error) {
	s, e := p.repository.GetPlan(ctx, id)
	return s.Plan, e
}
func (p transferApprovalPlans) ValidateCurrent(ctx context.Context, plan generated.Plan) error {
	s, e := p.repository.GetPlan(ctx, plan.PlanID)
	if e != nil {
		return e
	}
	r, e := p.repository.CurrentRevision(ctx)
	if e != nil {
		return e
	}
	if s.Plan.PlanDigest != plan.PlanDigest || r.StateRevision != plan.Binding.StateRevision || r.RecoveryEpoch != plan.Binding.RecoveryEpoch {
		return fmt.Errorf("approval plan changed")
	}
	return nil
}

// Only the Slack wire and synthetic token are substituted. The actual adapter
// decodes the envelope and the store-backed service authorizes and records it.
type transferApprovalWire struct{ incoming chan []byte }

func (w *transferApprovalWire) Open(context.Context, []byte) (slack.Socket, error) { return w, nil }
func (w *transferApprovalWire) Publish(_ context.Context, _ []byte, _, _, _ string, c acknowledgement.RequestCard) error {
	b, _ := json.Marshal(map[string]any{"planId": c.Request.PlanID, "planDigest": c.Request.PlanDigest, "targetDigest": c.Request.TargetDigest, "reasonDigest": c.Request.ReasonDigest, "nonce": c.Nonce, "stateRevision": c.Request.StateRevision, "recoveryEpoch": c.Request.RecoveryEpoch, "expiresAt": c.Request.ExpiresAt})
	raw, _ := json.Marshal(map[string]any{"envelope_id": "transfer-approval", "type": "interactive", "payload": map[string]any{"type": "block_actions", "team": map[string]string{"id": "T-transfer"}, "user": map[string]string{"id": "U-transfer"}, "actions": []map[string]string{{"action_id": "approve", "value": string(b)}}}})
	w.incoming <- raw
	return nil
}
func (w *transferApprovalWire) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-w.incoming:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (*transferApprovalWire) Acknowledge(context.Context, string) error { return nil }
func (*transferApprovalWire) Close() error                              { return nil }

type transferApprovalCredential struct{}

func (transferApprovalCredential) Resolve(context.Context, credentialref.Reference) ([]byte, error) {
	return []byte("synthetic-transfer-token"), nil
}
func approveTransferPlan(t *testing.T, ctx context.Context, authority *store.Store, path string, p generated.Plan, clock func() time.Time) generated.Acknowledgement {
	t.Helper()
	db := replacementRestoreDB(t, path)
	seen := map[string]bool{}
	for _, op := range p.Operations {
		if seen[op.TargetID] {
			continue
		}
		seen[op.TargetID] = true
		replacementRestoreExec(t, db, `INSERT INTO effective_authorization_grants VALUES(?,'restore-human','control-plane-admin','acknowledge','plan.acknowledge','plan-target',?,'human',1,'active','now','now')`, "restore-ack-"+op.TargetID, op.TargetID)
	}
	db.Close()
	service, e := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(authority), Plans: transferApprovalPlans{store.NewPlanRepository(authority)}, Authorizer: authorization.NewEvaluator(store.NewEffectiveAuthorizationRepository(authority)), Clock: clock})
	if e != nil {
		t.Fatal(e)
	}
	human := identity.Principal{ID: "restore-human", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
	for target := range seen {
		decision, err := authorization.NewEvaluator(store.NewEffectiveAuthorizationRepository(authority)).Authorize(ctx, human, authorization.Request{Action: authorization.ActionAcknowledge, Target: authorization.Target{Capability: "plan.acknowledge", ResourceKind: "plan-target", ResourceID: target}, Plan: &p, Branches: []authorization.Branch{authorization.BranchHuman}})
		if err != nil || !decision.Allowed {
			t.Fatalf("restore approval decision target=%s reason=%s state=%d/%d epoch=%d/%d risk=%s error=%v", target, decision.ReasonCode, decision.StateRevision, p.Binding.StateRevision, decision.RecoveryEpoch, p.Binding.RecoveryEpoch, decision.Risk, err)
		}
	}
	card, e := service.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-slack", Nonce: "restore-approval-nonce"}, p.PlanID)
	if e != nil {
		t.Fatalf("request restore approval: %v", e)
	}
	wire := &transferApprovalWire{incoming: make(chan []byte, 1)}
	results := make(chan generated.Acknowledgement, 1)
	failures := make(chan error, 1)
	sink := slack.CandidateSinkFuncs{SubmitFunc: func(c context.Context, v acknowledgement.Candidate) error {
		a, e := service.Decide(c, v)
		if e != nil {
			failures <- e
		} else {
			results <- a
		}
		return e
	}, RejectFunc: func(_ context.Context, r acknowledgement.AdapterRejection) error {
		e := fmt.Errorf("Slack rejection: %s", r.ReasonCode)
		failures <- e
		return e
	}}
	adapter, e := slack.NewAdapter(slack.Config{AppTokenReference: credentialref.Reference{ID: "synthetic-app", Consumer: "slack-acknowledgement"}, BotTokenReference: credentialref.Reference{ID: "synthetic-bot", Consumer: "slack-acknowledgement"}, WorkspaceID: "T-transfer", SlackUserID: "U-transfer", HumanID: human.ID, AuthorityID: "fixture-slack", ChannelID: "C-transfer", ApproveActionID: "approve", RejectActionID: "reject", ReconnectDelay: time.Millisecond}, transferApprovalCredential{}, wire, sink)
	if e != nil {
		t.Fatal(e)
	}
	runctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- adapter.Run(runctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("approval adapter did not stop")
		}
	}()
	if e = adapter.Publish(runctx, card); e != nil {
		t.Fatal(e)
	}
	select {
	case a := <-results:
		return a
	case e := <-failures:
		t.Fatal(e)
	case <-runctx.Done():
		t.Fatal("restore approval timed out")
	}
	return generated.Acknowledgement{}
}
