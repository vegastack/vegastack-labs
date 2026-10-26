package cloudflare

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"slices"
	"sync"
)

type ingressCompleted struct {
	staged    ingress.Staged
	binding   adapter.ExactExecutionBinding
	snapshot  ingress.Snapshot
	operation adapter.Operation
}
type IngressAdapter struct {
	Authority ingress.Authority
	Backend   IngressBackend
	mu        sync.Mutex
	completed map[string]ingressCompleted
}

func (a *IngressAdapter) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	return adapter.Effect{}, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
}
func (a *IngressAdapter) ExecuteBoundWithCredentials(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, values []*credentialref.Value) (adapter.Effect, error) {
	if a == nil || a.Authority == nil || a.Backend == nil || adapter.ValidateOperation(op) != nil {
		return adapter.Effect{}, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	d, e := a.Authority.Resolve(ctx, op, b)
	if e != nil {
		return adapter.Effect{}, e
	}
	if len(d.Bindings) != len(values) || len(values) == 0 {
		return adapter.Effect{}, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	read, write, replacement := -1, -1, -1
	for i, x := range d.Bindings {
		switch x.PurposeID {
		case ingress.PurposeRead:
			read = i
		case ingress.PurposeWrite:
			write = i
		case ingress.PurposeReplacement:
			replacement = i
		}
	}
	if read < 0 {
		return adapter.Effect{}, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	q := d.Request.Change
	before, e := a.Backend.ObserveIngress(ctx, q, values[read])
	if e != nil {
		return adapter.Effect{}, e
	}
	if !before.Present || before.Digest != q.BeforeDigest {
		return adapter.Effect{}, ingress.Error(generated.ErrorCodePlanStale)
	}
	if _, e = a.Authority.Resolve(ctx, op, b); e != nil {
		return adapter.Effect{}, e
	}
	after := before
	partial := func(reason string, observed bool) (adapter.Effect, error) {
		after.Reason = reason
		after.Digest = ingress.Digest([]string{b.RunID, b.StepID, reason})
		if e := a.Authority.Record(context.WithoutCancel(ctx), d, b, after, "partial"); e != nil {
			return adapter.Effect{Status: "partial", ResultDigest: after.Digest, Changed: true, EffectObserved: observed}, e
		}
		return adapter.Effect{Status: "partial", ResultDigest: after.Digest, Changed: true, EffectObserved: observed}, nil
	}
	if q.Action != "import" {
		if write < 0 {
			return adapter.Effect{}, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		var secret *credentialref.Value
		if q.Action == "token-rotate" {
			if replacement < 0 {
				return adapter.Effect{}, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
			}
			secret = values[replacement]
		}
		if e = a.Backend.MutateIngress(ctx, q, values[write], secret); e != nil {
			return partial("provider-effect-uncertain", false)
		}
		if q.Action == "token-rotate" {
			return partial("connector-update-required", true)
		}
		after, e = a.Backend.ObserveIngress(ctx, q, values[read])
		if e != nil || !matchesIngress(q, after) {
			return partial("provider-verification-pending", true)
		}
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
func (a *IngressAdapter) Verify(ctx context.Context, op adapter.Operation, effect adapter.Effect) (adapter.Verification, error) {
	a.mu.Lock()
	d, ok := a.completed[effect.ResultDigest]
	delete(a.completed, effect.ResultDigest)
	a.mu.Unlock()
	if !ok || effect.Status != "succeeded" || d.operation.OperationID != op.OperationID || d.operation.OperationType != op.OperationType || d.operation.AdapterID != op.AdapterID || d.operation.ExecutorID != op.ExecutorID || d.operation.TargetID != op.TargetID || d.operation.InputDigest != op.InputDigest || d.operation.ArtifactDigest != op.ArtifactDigest {
		return adapter.Verification{Digest: effect.ResultDigest}, ingress.Error(generated.ErrorCodeIntegrityFailure)
	}
	fail := func(e error) (adapter.Verification, error) {
		s := d.snapshot
		s.Reason = "provider-verification-incomplete"
		s.Digest = ingress.Digest([]string{d.binding.RunID, d.binding.StepID, s.Reason})
		_ = a.Authority.Record(context.WithoutCancel(ctx), d.staged, d.binding, s, "partial")
		return adapter.Verification{Digest: effect.ResultDigest}, e
	}
	if _, e := a.Authority.Resolve(ctx, op, d.binding); e != nil {
		return fail(e)
	}
	v, e := a.Authority.BorrowRead(ctx, d.staged)
	if e != nil {
		return fail(e)
	}
	defer v.Close()
	s, e := a.Backend.ObserveIngress(ctx, d.staged.Request.Change, v)
	if e != nil || s.Digest != d.snapshot.Digest {
		return fail(ingress.Error(generated.ErrorCodeIntegrityFailure))
	}
	if e = a.Authority.Record(ctx, d.staged, d.binding, s, "observed"); e != nil {
		return fail(e)
	}
	return adapter.Verification{Verified: true, Digest: effect.ResultDigest}, nil
}
func matchesIngress(q generated.IngressChange, s ingress.Snapshot) bool {
	switch q.Action {
	case "tunnel-config-update":
		return s.Present && s.Hostname == q.Hostname && s.OriginService == q.OriginService && s.OriginServerName == q.OriginServerName && s.OriginTLSVerified
	case "access-policy-update":
		a, b := slices.Clone(q.AllowedGroupIDs), slices.Clone(s.AllowedGroupIDs)
		slices.Sort(a)
		slices.Sort(b)
		return s.PolicyName == q.PolicyName && s.Precedence == q.Precedence && slices.Equal(a, b)
	case "dns-record-update":
		return s.DNSName == q.Hostname && s.DNSContent == q.TunnelID+".cfargotunnel.com" && s.DNSProxied
	case "connector-disconnect":
		return !s.Present
	}
	return false
}

var _ adapter.BoundCredentialExecutor = (*IngressAdapter)(nil)
