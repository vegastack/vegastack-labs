package cloudflare

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
)

type IngressBootstrapBackend interface {
	ObserveBootstrap(context.Context, generated.IngressChange, *credentialref.Value) (ingress.Snapshot, error)
	MutateBootstrap(context.Context, generated.IngressChange, *credentialref.Value, *credentialref.Value) (ingress.Snapshot, error)
}
type ingressBootstrapReservation interface {
	ReserveBootstrap(context.Context, ingress.Staged, adapter.ExactExecutionBinding, ingress.Snapshot) error
}

func (a *IngressAdapter) executeBootstrap(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, d ingress.Staged, values []*credentialref.Value, read, write int) (adapter.Effect, error) {
	backend, ok := a.Backend.(IngressBootstrapBackend)
	reservation, canReserve := a.Authority.(ingressBootstrapReservation)
	if !ok || !canReserve || write < 0 {
		return adapter.Effect{}, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	q := d.Request.Change
	before, e := backend.ObserveBootstrap(ctx, q, values[read])
	if e != nil {
		return adapter.Effect{}, e
	}
	if before.Digest != q.BeforeDigest {
		return adapter.Effect{}, ingress.Error(generated.ErrorCodePlanStale)
	}
	if _, e = a.Authority.Resolve(ctx, op, b); e != nil {
		return adapter.Effect{}, e
	}
	if e = reservation.ReserveBootstrap(ctx, d, b, before); e != nil {
		return adapter.Effect{}, e
	}
	// Reservation is durable even if authority changes or the provider response is
	// lost. Such a run is partial; no fresh plan may blindly create another object.
	partial := func(s ingress.Snapshot, reason string) (adapter.Effect, error) {
		s.Reason = reason
		s.Digest = ingress.Digest([]string{b.RunID, b.StepID, reason, s.ResourceID})
		e := a.Authority.Record(context.WithoutCancel(ctx), d, b, s, "partial")
		return adapter.Effect{Status: "partial", ResultDigest: s.Digest, Changed: true, EffectObserved: s.ResourceID != ""}, e
	}
	if _, e = a.Authority.Resolve(ctx, op, b); e != nil {
		return partial(ingress.Snapshot{}, "bootstrap-authority-changed")
	}
	after, e := backend.MutateBootstrap(ctx, q, values[read], values[write])
	if e != nil {
		return partial(after, "provider-effect-uncertain")
	}
	if after.ResourceID == "" || !after.Present {
		return partial(after, "provider-verification-pending")
	}
	if _, e = a.Authority.Resolve(ctx, op, b); e != nil {
		return partial(after, "bootstrap-authority-changed")
	}
	observedQ := q
	observedQ.ResourceID = after.ResourceID
	observed, e := backend.ObserveBootstrap(ctx, observedQ, values[read])
	if e != nil || !observed.Present || observed.ResourceID != after.ResourceID || observed.Digest != after.Digest {
		return partial(after, "provider-verification-pending")
	}
	result := ingress.Digest([]any{b.RunID, b.StepID, after.Digest})
	a.mu.Lock()
	if a.completed == nil {
		a.completed = map[string]ingressCompleted{}
	}
	a.completed[result] = ingressCompleted{d, b, after, op}
	a.mu.Unlock()
	return adapter.Effect{Status: "succeeded", ResultDigest: result, Changed: true, EffectObserved: true}, nil
}
