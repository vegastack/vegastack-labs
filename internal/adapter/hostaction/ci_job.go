package hostaction

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	protocol "github.com/vegastack/vegastack-labs/internal/hostaction"
	"io"
)

// CIControl is a finite server-owned peer on an already authenticated SSH stream.
// It is never selected by an action input or an unsigned request.
type CIControl interface {
	Exchange(context.Context, generated.HostActionBundle, io.Reader, io.WriteCloser) error
	Finish(context.Context, generated.HostActionBundle, generated.HostActionResult) error
}
type CIControlFactory interface {
	NewCIControl(context.Context, adapter.Operation, adapter.ExactExecutionBinding, []*credentialref.Value) (CIControl, error)
}

func (a *Adapter) ConfigureCI(factory CIControlFactory) error {
	if a == nil || factory == nil {
		return denied()
	}
	a.ci = factory
	return nil
}
func (a *Adapter) executeCI(ctx context.Context, op adapter.Operation, binding adapter.ExactExecutionBinding, values []*credentialref.Value) (adapter.Effect, error) {
	if a.ci == nil || len(op.SecretReferences) != 3 || len(values) != 3 {
		return adapter.Effect{}, denied()
	}
	for _, v := range values {
		if v == nil || len(v.Bytes()) == 0 {
			return adapter.Effect{}, denied()
		}
	}
	control, e := a.ci.NewCIControl(ctx, op, binding, values)
	if e != nil {
		return adapter.Effect{}, e
	}
	envelope, e := a.bundles.Issue(ctx, op, binding)
	if e != nil {
		return adapter.Effect{}, e
	}
	b := envelope.Bundle
	if b.ActionID != protocol.CIJobAction || b.ActionVersion != "1.0.0" || b.PlanID != binding.PlanID || b.PlanDigest != binding.PlanDigest || b.RunID != binding.RunID || b.StepID != binding.StepID || b.LeaseID != binding.LeaseID || b.StateRevision != binding.StateRevision || b.RecoveryEpoch != binding.RecoveryEpoch || b.HostID != op.TargetID {
		return adapter.Effect{}, denied()
	}
	digest, e := protocol.BundleDigest(b)
	if e != nil {
		return adapter.Effect{}, e
	}
	target, e := a.targets.Resolve(ctx, b)
	if e != nil || !validTarget(target, b) {
		return adapter.Effect{}, denied()
	}
	var sshValue *credentialref.Value
	for i, ref := range op.SecretReferences {
		if ref.ID == b.CredentialReferenceID {
			if sshValue != nil {
				return adapter.Effect{}, denied()
			}
			sshValue = values[i]
		}
	}
	if sshValue == nil {
		return adapter.Effect{}, denied()
	}
	result, observed, e := a.exchangeOne(ctx, target, envelope, digest, sshValue, nil, nil, nil, "", control)
	effect := adapter.Effect{EffectObserved: observed}
	if e != nil {
		return effect, e
	}
	effect = adapter.Effect{Status: result.Status, ResultDigest: result.ResultDigest, Changed: result.Changed, EffectObserved: result.EffectObserved}
	if e = control.Finish(ctx, b, result); e != nil {
		return effect, e
	}
	if adapter.ValidateEffect(effect) != nil {
		return effect, denied()
	}
	if e = a.remember(op, binding, effect, result); e != nil {
		return effect, e
	}
	return effect, nil
}
