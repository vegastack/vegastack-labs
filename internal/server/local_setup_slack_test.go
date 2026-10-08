package server

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
	"time"
)

func TestLocalSetupApprovalRejectsUnboundCandidate(t *testing.T) {
	pending := &pendingSetupApproval{}
	if err := pending.Submit(context.Background(), acknowledgement.Candidate{}); err == nil {
		t.Fatal("unbound candidate authorized setup")
	}
}

func setupPendingFixture(t *testing.T) (*pendingSetupApproval, acknowledgement.Candidate) {
	t.Helper()
	now := time.Now()
	request := validLocalSetupRequest(now)
	raw, _ := json.Marshal(request)
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	delete(fields, "requestNonce")
	fields["requestNonceDigest"] = setupSHA256([]byte(request.RequestNonce))
	fields["schema"] = generated.SchemaIDLocalSetupReviewRequest
	sanitized, _ := json.Marshal(fields)
	var reviewed generated.LocalSetupReviewRequest
	_ = json.Unmarshal(sanitized, &reviewed)
	value := store.InitialSetupReview{Request: reviewed, RequestDigest: setupSHA256(raw), Acknowledgement: store.InitialAcknowledgementBinding{HumanID: request.InitialHumanID, AuthorityID: "authority-setup", Method: identity.SlackSocketModeMethod}}
	canonical, _ := json.Marshal(value)
	review := localSetupReview{request: request, slack: slackAcknowledgementProfile{AuthorityID: "authority-setup"}, canonical: canonical, digest: setupSHA256(canonical), readable: string(canonical)}
	pending, err := newPendingSetupApproval(review, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	// Unit-level candidate comparison: whole-flow tests use actual receipt I/O.
	pending.persist = func(context.Context, store.InitialSetupApproval) error { return nil }
	card := pending.Card()
	expires, _ := time.Parse(time.RFC3339Nano, card.Request.ExpiresAt)
	candidate := acknowledgement.Candidate{Human: identity.Principal{ID: request.InitialHumanID, Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}, AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove, PlanID: card.Request.PlanID, PlanDigest: card.Request.PlanDigest, TargetDigest: card.Request.TargetDigest, ReasonDigest: card.Request.ReasonDigest, Nonce: card.Nonce, ExpiresAt: expires, DecidedAt: time.Now()}
	return pending, candidate
}
func TestLocalSetupApprovalExactAndSingleUse(t *testing.T) {
	for name, mutate := range map[string]func(*acknowledgement.Candidate){
		"human": func(c *acknowledgement.Candidate) { c.Human.ID = "other" }, "method": func(c *acknowledgement.Candidate) { c.Human.Method = "local-os-peer" }, "kind": func(c *acknowledgement.Candidate) { c.Human.Kind = identity.PrincipalAgent },
		"authority": func(c *acknowledgement.Candidate) { c.AuthorityID = "other" }, "action": func(c *acknowledgement.Candidate) { c.Action = "yes" }, "plan": func(c *acknowledgement.Candidate) { c.PlanID = "other" }, "digest": func(c *acknowledgement.Candidate) { c.PlanDigest = "other" }, "target": func(c *acknowledgement.Candidate) { c.TargetDigest = "other" }, "reason": func(c *acknowledgement.Candidate) { c.ReasonDigest = "other" }, "nonce": func(c *acknowledgement.Candidate) { c.Nonce = "other" }, "revision": func(c *acknowledgement.Candidate) { c.StateRevision = 1 }, "epoch": func(c *acknowledgement.Candidate) { c.RecoveryEpoch = 1 }, "expiry": func(c *acknowledgement.Candidate) { c.ExpiresAt = c.ExpiresAt.Add(time.Second) }, "old-decision": func(c *acknowledgement.Candidate) { c.DecidedAt = time.Time{} }, "future-decision": func(c *acknowledgement.Candidate) { c.DecidedAt = c.DecidedAt.Add(time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			pending, candidate := setupPendingFixture(t)
			mutate(&candidate)
			if pending.Submit(context.Background(), candidate) == nil {
				t.Fatal("mismatch approved")
			}
			select {
			case <-pending.done:
				t.Fatal("invalid input completed approval")
			default:
			}
		})
	}
	pending, candidate := setupPendingFixture(t)
	if err := pending.Submit(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	approval, err := pending.Wait(context.Background())
	if err != nil || approval.HumanID != candidate.Human.ID {
		t.Fatal("valid approval missing", err)
	}
	if pending.Submit(context.Background(), candidate) == nil {
		t.Fatal("approval replay accepted")
	}
	other, _ := setupPendingFixture(t)
	if other.Submit(context.Background(), candidate) == nil {
		t.Fatal("old challenge authorized new attempt")
	}
}
func TestLocalSetupApprovalRejectCancelExpiry(t *testing.T) {
	pending, candidate := setupPendingFixture(t)
	candidate.Action = acknowledgement.ActionReject
	if pending.Submit(context.Background(), candidate) == nil {
		t.Fatal("rejection succeeded")
	}
	if _, err := pending.Wait(context.Background()); err == nil {
		t.Fatal("rejection approved")
	}
	pending, _ = setupPendingFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := pending.Wait(ctx); err == nil {
		t.Fatal("cancel approved")
	}
	pending, candidate = setupPendingFixture(t)
	pending.clock = func() time.Time { return pending.expires }
	if pending.Submit(context.Background(), candidate) == nil {
		t.Fatal("expired approval accepted")
	}
}

func TestLocalSetupApprovalWaitsForDurability(t *testing.T) {
	pending, candidate := setupPendingFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	pending.persist = func(context.Context, store.InitialSetupApproval) error {
		close(entered)
		<-release
		return errors.New("synthetic receipt failure")
	}
	returned := make(chan error, 1)
	go func() { returned <- pending.Submit(context.Background(), candidate) }()
	<-entered
	select {
	case <-pending.done:
		t.Fatal("approval signalled before durability")
	default:
	}
	select {
	case <-returned:
		t.Fatal("provider success before durability")
	default:
	}
	close(release)
	if err := <-returned; err == nil {
		t.Fatal("failed receipt returned success")
	}
	if _, err := pending.Wait(context.Background()); err == nil {
		t.Fatal("failed receipt yielded approval")
	}
}
