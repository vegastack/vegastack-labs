//go:build linux

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapters/slack"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// Only provider credentials and Socket Mode transport are synthetic. Actual
// Slack envelope decoding and identity binding precede the real store-backed
// acknowledgement service, just as in the server's existing acceptance.
func approveHostLifecycleViaSlack(t *testing.T, service *acknowledgement.Service, card acknowledgement.RequestCard) generated.Acknowledgement {
	t.Helper()
	wire := &lifecycleSlackTransport{cards: make(chan acknowledgement.RequestCard, 1), incoming: make(chan []byte, 1)}
	type outcome struct {
		ack generated.Acknowledgement
		err error
	}
	results := make(chan outcome, 1)
	sink := slack.CandidateSinkFuncs{SubmitFunc: func(ctx context.Context, c acknowledgement.Candidate) error {
		a, e := service.Decide(ctx, c)
		select {
		case results <- outcome{a, e}:
		case <-ctx.Done():
		}
		return e
	}, RejectFunc: func(ctx context.Context, r acknowledgement.AdapterRejection) error {
		e := fmt.Errorf("synthetic Slack envelope rejected: %s", r.ReasonCode)
		select {
		case results <- outcome{err: e}:
		case <-ctx.Done():
		}
		return e
	}}
	config := slack.Config{AppTokenReference: credentialref.Reference{ID: "synthetic-app", Consumer: "slack-acknowledgement"}, BotTokenReference: credentialref.Reference{ID: "synthetic-bot", Consumer: "slack-acknowledgement"}, WorkspaceID: "T-lifecycle", SlackUserID: "U-lifecycle", HumanID: card.Request.HumanID, AuthorityID: card.Request.AuthorityID, ChannelID: "C-lifecycle", ApproveActionID: "approve", RejectActionID: "reject", ReconnectDelay: time.Millisecond}
	adapter, e := slack.NewAdapter(config, lifecycleSlackCredential{}, wire, sink)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- adapter.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("Slack fixture did not stop")
		}
	}()
	if e = adapter.Publish(ctx, card); e != nil {
		t.Fatal(e)
	}
	var published acknowledgement.RequestCard
	select {
	case published = <-wire.cards:
	case <-ctx.Done():
		t.Fatal("Slack card was not published")
	}
	binding := map[string]any{"planId": published.Request.PlanID, "planDigest": published.Request.PlanDigest, "targetDigest": published.Request.TargetDigest, "reasonDigest": published.Request.ReasonDigest, "nonce": published.Nonce, "stateRevision": published.Request.StateRevision, "recoveryEpoch": published.Request.RecoveryEpoch, "expiresAt": published.Request.ExpiresAt}
	value, e := json.Marshal(binding)
	if e != nil {
		t.Fatal(e)
	}
	envelope := map[string]any{"envelope_id": "lifecycle-envelope", "type": "interactive", "accepts_response_payload": true, "payload": map[string]any{
		"type": "block_actions", "api_app_id": "A-lifecycle", "trigger_id": "synthetic-trigger", "response_url": "https://example.invalid/synthetic", "is_enterprise_install": false,
		"team": map[string]string{"id": "T-lifecycle", "domain": "synthetic"}, "user": map[string]string{"id": "U-lifecycle", "username": "synthetic", "team_id": "T-lifecycle"},
		"container": map[string]any{"type": "message", "message_ts": "1.0", "channel_id": "C-lifecycle", "is_ephemeral": false}, "channel": map[string]string{"id": "C-lifecycle", "name": "lifecycle"},
		"message": map[string]any{"type": "message", "ts": "1.0", "text": published.ReviewText},
		"actions": []map[string]string{{"action_id": "approve", "block_id": "lifecycle-actions", "type": "button", "action_ts": "1.0", "value": string(value)}}}}
	raw, e := json.Marshal(envelope)
	if e != nil {
		t.Fatal(e)
	}
	wire.incoming <- raw
	select {
	case result := <-results:
		if result.err != nil {
			t.Fatal(result.err)
		}
		return result.ack
	case <-ctx.Done():
		t.Fatal("Slack approval timed out")
	}
	return generated.Acknowledgement{}
}

type lifecycleSlackCredential struct{}

func (lifecycleSlackCredential) Resolve(context.Context, credentialref.Reference) ([]byte, error) {
	return []byte("synthetic-lifecycle-token"), nil
}

type lifecycleSlackTransport struct {
	cards    chan acknowledgement.RequestCard
	incoming chan []byte
}

func (w *lifecycleSlackTransport) Open(context.Context, []byte) (slack.Socket, error) { return w, nil }
func (w *lifecycleSlackTransport) Publish(ctx context.Context, _ []byte, _ string, _ string, _ string, c acknowledgement.RequestCard) error {
	select {
	case w.cards <- c:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (w *lifecycleSlackTransport) Receive(ctx context.Context) ([]byte, error) {
	select {
	case raw := <-w.incoming:
		return raw, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (*lifecycleSlackTransport) Acknowledge(context.Context, string) error { return nil }
func (*lifecycleSlackTransport) Close() error                              { return nil }

// The configured recipient is fixture policy, never an identity supplied by the
// browser. Issuance and status use the actual public handlers; approval still
// enters via the real Slack decoder above.
type lifecycleApprovalScope struct{}

func (lifecycleApprovalScope) Resolve(context.Context, generated.AcknowledgementRequest) (acknowledgement.Scope, error) {
	return acknowledgement.Scope{}, fmt.Errorf("legacy acknowledgement request not used")
}
func (lifecycleApprovalScope) ResolvePlan(ctx context.Context, p generated.Plan) (acknowledgement.Scope, error) {
	principal, ok := identity.PrincipalFromContext(ctx)
	if !ok || principal.ID != "human-a" || identity.EffectivePrincipalKind(principal) != identity.PrincipalHuman {
		return acknowledgement.Scope{}, fmt.Errorf("wrong configured recipient")
	}
	return acknowledgement.Scope{Human: principal, AuthorityID: "fixture-authority", Nonce: "browser-approval-" + p.PlanID}, nil
}

type lifecycleApprovalPublisher struct {
	t       *testing.T
	service *acknowledgement.Service
}

func (p lifecycleApprovalPublisher) Publish(_ context.Context, c acknowledgement.RequestCard) error {
	approveHostLifecycleViaSlack(p.t, p.service, c)
	return nil
}
func registerLifecycleBrowserApproval(t *testing.T, app *Application, service *acknowledgement.Service, plans PlanService, factory *result.Factory) {
	t.Helper()
	if err := RegisterAcknowledgementOperations(app, AcknowledgementOperationConfig{Plans: plans, Acknowledgements: service, Scopes: lifecycleApprovalScope{}, Publisher: lifecycleApprovalPublisher{t, service}, Results: factory}); err != nil {
		t.Fatal(err)
	}
}
func requestLifecycleBrowserApproval(t *testing.T, serve func(string, string, any) *httptest.ResponseRecorder, seed admissionSQL, p generated.Plan, at *time.Time) {
	t.Helper()
	*at = time.Now().UTC().Truncate(time.Second)
	for _, x := range [][2]string{{"author", "plan.acknowledgement.request"}, {"read", "plan.acknowledgement.read"}} {
		seed.exec(`INSERT INTO effective_authorization_grants VALUES(?,'human-a','control-plane-admin',?,?,'plan',?,NULL,1,'active','now','now')`, p.PlanID+"-"+x[1], x[0], x[1], p.PlanID)
	}
	seed.exec(`INSERT INTO read_grants VALUES('human-a','plan.acknowledgement.read','plan',?,1,'active','now','now')`, p.PlanID)
	ref := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, RecoveryEpoch: p.Binding.RecoveryEpoch, IdempotencyKey: "request-approval-" + p.PlanID, Extensions: []generated.ContractExtension{}}
	w := serve(http.MethodPost, "/api/v1/plans/"+p.PlanID+"/approval-request", ref)
	if w.Code != 200 {
		t.Fatalf("browser approval request: %d %s", w.Code, w.Body.String())
	}
	w = serve(http.MethodGet, "/api/v1/plans/"+p.PlanID+"/approval-status", nil)
	if w.Code != 200 {
		t.Fatalf("browser approval status: %d %s", w.Code, w.Body.String())
	}
	var envelope struct{ Data generated.ApprovalStatus }
	if json.Unmarshal(w.Body.Bytes(), &envelope) != nil || envelope.Data.Status != "approved" || !envelope.Data.AuthorizationCurrent || !envelope.Data.CanApply || envelope.Data.PlanID != p.PlanID || envelope.Data.PlanDigest != p.PlanDigest {
		t.Fatalf("browser exact approval: %s", w.Body.String())
	}
}
