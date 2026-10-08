package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type pendingSetupApproval struct {
	persist          func(context.Context, store.InitialSetupApproval) error
	mu               sync.Mutex
	card             acknowledgement.RequestCard
	clock            func() time.Time
	created, expires time.Time
	requestDigest    string
	done             chan struct{}
	terminal         bool
	approval         store.InitialSetupApproval
	err              error
}

func newPendingSetupApproval(review localSetupReview, clock func() time.Time) (*pendingSetupApproval, error) {
	if clock == nil || review.digest == "" || review.digest != setupSHA256(review.canonical) || review.readable == "" {
		return nil, setupFailure(generated.ErrorCodeInputInvalid)
	}
	if err := validateLocalSetupRequest(review.request, clock()); err != nil {
		return nil, err
	}
	var frozen store.InitialSetupReview
	if json.Unmarshal(review.canonical, &frozen) != nil || frozen.RequestDigest == "" || frozen.Acknowledgement.Method != identity.SlackSocketModeMethod || frozen.Acknowledgement.HumanID != review.request.InitialHumanID || frozen.Acknowledgement.AuthorityID != review.slack.AuthorityID {
		return nil, setupFailure(generated.ErrorCodeInputInvalid)
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, setupFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	nonce := hex.EncodeToString(challenge)
	expiry, _ := time.Parse(time.RFC3339Nano, review.request.ExpiresAt)
	p := &pendingSetupApproval{clock: clock, created: clock().UTC().Truncate(time.Second), expires: expiry, done: make(chan struct{}), requestDigest: frozen.RequestDigest}
	p.card = acknowledgement.RequestCard{ReviewText: review.readable, AcknowledgementID: "setup-" + review.request.SetupID, Nonce: nonce, Request: generated.AcknowledgementRequest{Schema: generated.SchemaIDAcknowledgementRequest, SchemaVersion: "1.0.0", PlanID: review.request.SetupID, PlanDigest: review.digest, TargetDigest: review.digest, ReasonDigest: setupSHA256([]byte("initialize-local-control-service")), HumanID: review.request.InitialHumanID, AuthorityID: review.slack.AuthorityID, NonceDigest: setupSHA256([]byte(nonce)), StateRevision: 0, RecoveryEpoch: 0, ExpiresAt: expiry.UTC().Format(time.RFC3339Nano), Extensions: []generated.ContractExtension{}}}
	return p, nil
}
func (p *pendingSetupApproval) Card() acknowledgement.RequestCard { return p.card }
func (p *pendingSetupApproval) Submit(ctx context.Context, c acknowledgement.Candidate) error {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return setupFailure(generated.ErrorCodeAuthorizationDenied)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.clock == nil || p.done == nil || p.terminal {
		return setupFailure(generated.ErrorCodeAuthorizationDenied)
	}
	r := p.card.Request
	now := p.clock()
	if c.Human.ID != r.HumanID || c.Human.Kind != identity.PrincipalHuman || c.Human.Method != identity.SlackSocketModeMethod || c.AuthorityID != r.AuthorityID || c.PlanID != r.PlanID || c.PlanDigest != r.PlanDigest || c.TargetDigest != r.TargetDigest || c.ReasonDigest != r.ReasonDigest || c.Nonce != p.card.Nonce || c.StateRevision != 0 || c.RecoveryEpoch != 0 || !c.ExpiresAt.Equal(p.expires) || !now.Before(p.expires) || c.DecidedAt.Before(p.created) || c.DecidedAt.After(now) || !c.DecidedAt.Before(p.expires) {
		return setupFailure(generated.ErrorCodeAuthorizationDenied)
	}
	if c.Action != acknowledgement.ActionApprove && c.Action != acknowledgement.ActionReject {
		return setupFailure(generated.ErrorCodeAuthorizationDenied)
	}
	p.terminal = true
	if c.Action == acknowledgement.ActionReject {
		p.err = setupFailure(generated.ErrorCodeAuthorizationDenied)
	} else {
		approval := store.InitialSetupApproval{HumanID: c.Human.ID, Method: c.Human.Method, AuthorityID: c.AuthorityID, ReviewDigest: r.PlanDigest, RequestDigest: p.requestDigest, DecidedAt: c.DecidedAt}
		if p.persist == nil {
			p.err = setupFailure(generated.ErrorCodePrerequisiteBlocked)
		} else {
			p.err = p.persist(ctx, approval)
		}
		if p.err == nil {
			p.approval = approval
		}
	}
	close(p.done)
	return p.err
}
func (p *pendingSetupApproval) Reject(context.Context, acknowledgement.AdapterRejection) error {
	// Invalid provider envelopes never create an approval or durable authority.
	return setupFailure(generated.ErrorCodeAuthorizationDenied)
}
func (p *pendingSetupApproval) Wait(ctx context.Context) (store.InitialSetupApproval, error) {
	if p == nil || p.done == nil {
		return store.InitialSetupApproval{}, setupFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	timer := time.NewTimer(time.Until(p.expires))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return store.InitialSetupApproval{}, setupFailure(generated.ErrorCodeInterrupted)
	case <-timer.C:
		return store.InitialSetupApproval{}, setupFailure(generated.ErrorCodeAuthorizationDenied)
	case <-p.done:
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return store.InitialSetupApproval{}, p.err
	}
	if !p.clock().Before(p.expires) {
		return store.InitialSetupApproval{}, setupFailure(generated.ErrorCodeAuthorizationDenied)
	}
	return p.approval, nil
}
