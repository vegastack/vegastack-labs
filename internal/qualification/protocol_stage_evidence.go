package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"time"
)

// ValidateActionProtocolEvidence requires both this controller's real transport
// observation and independent target-side receipt recollection. A failed
// product receipt or a caller-reported exit status cannot satisfy it.
func ValidateActionProtocolEvidence(scenario string, executions []ProducerExecution, observations []generated.NativeObservation) error {
	if len(executions) != 1 || len(observations) != 1 {
		return ErrUnavailable
	}
	e, o := executions[0], observations[0]
	request, err := producerAction(e)
	if err != nil || request.ActionID != "debian.access.collect" || o.ActionProtocol == nil || o.ActionReceiptBefore == nil || o.ActionReceiptAfter == nil {
		return ErrUnavailable
	}
	w := *o.ActionProtocol
	b := w.Bundle
	digest, err := hostaction.BundleDigest(b)
	if err != nil || digest != e.Result.BundleDigest || b.PlanID != e.Reference.PlanID || b.PlanDigest != e.Reference.PlanDigest || b.RunID != e.Reference.RunID || b.StepID != e.Reference.StepID || b.LeaseID != e.Reference.LeaseID || b.RecoveryEpoch != e.Receipt.RecoveryEpoch || b.HostID != request.HostID || b.HostIdentityDigest != request.ConsoleConfirmation.HostIdentityDigest || b.ActionInput != request.ActionInput || b.ActionInputDigest != request.ActionInputDigest || b.ActionID != request.ActionID || b.ActionVersion != request.ActionVersion || w.ResultDigest != hostaction.Digest(*e.Result) {
		return ErrUnavailable
	}
	return validateProtocolWitness(scenario, w, *o.ActionReceiptBefore, *o.ActionReceiptAfter, o.ObservedAt)
}

func validateProtocolWitness(scenario string, w generated.NativeActionProtocolWitness, before, after generated.NativeActionReceiptWitness, observedAt string) error {
	count := int64(1)
	if scenario == "action-concurrency" {
		count = 3
	} else if scenario != "action-replay" {
		return ErrUnavailable
	}
	if !exactNativeJSON(generated.SchemaIDNativeActionProtocolWitness, w) || !exactNativeJSON(generated.SchemaIDNativeActionReceiptWitness, before) || !exactNativeJSON(generated.SchemaIDNativeActionReceiptWitness, after) || w.ScenarioID != scenario || w.Bundle.ActionID != "debian.access.collect" || w.ConcurrentAttempts != count || w.CompletedResults != 1 || int64(len(w.ConcurrentDenials)) != count-1 {
		return ErrUnavailable
	}
	digest, err := hostaction.BundleDigest(w.Bundle)
	if err != nil {
		return ErrUnavailable
	}
	execution := hostaction.ExecutionDigest(w.Bundle)
	claim := w.ReplayDenial.ClaimDigest
	if claim == "" || w.ReplayDenial.ResultDigest != w.ResultDigest {
		return ErrUnavailable
	}
	check := func(d generated.HostActionDenial, completed bool) bool {
		if d.Code != generated.ErrorCodeAuthorizationDenied || d.Phase != "execution-claim" || d.BundleDigest != digest || d.ExecutionDigest != execution {
			return false
		}
		if completed {
			return d.ClaimDigest == claim && d.ResultDigest == w.ResultDigest
		}
		return (d.ClaimDigest == "" && d.ResultDigest == "") || (d.ClaimDigest == claim && d.ResultDigest == w.ResultDigest)
	}
	if !check(w.ReplayDenial, true) || !check(w.ReplayAfterDenial, true) {
		return ErrUnavailable
	}
	for _, d := range w.ConcurrentDenials {
		if !check(d, false) {
			return ErrUnavailable
		}
	}
	wanted := map[string]bool{"malformed-envelope": false, "wrong-host": false, "wrong-plan": false, "wrong-epoch": false, "invalid-signature": false}
	if len(w.NegativeAttempts) != len(wanted) {
		return ErrUnavailable
	}
	for _, n := range w.NegativeAttempts {
		seen, ok := wanted[n.Variant]
		d := n.Denial
		if !ok || seen || d.Code != generated.ErrorCodeAuthorizationDenied || d.Phase != "envelope" || d.BundleDigest != "" || d.ExecutionDigest != "" || d.ClaimDigest != "" || d.ResultDigest != "" {
			return ErrUnavailable
		}
		wanted[n.Variant] = true
	}
	for _, r := range []generated.NativeActionReceiptWitness{before, after} {
		if hostaction.Digest(r.Bundle) != hostaction.Digest(w.Bundle) || r.ExecutionDigest != execution || r.BundleDigest != digest || r.ClaimDigest != claim || r.ResultDigest != w.ResultDigest || r.Status != "succeeded" {
			return ErrUnavailable
		}
	}
	at, e1 := time.Parse(time.RFC3339, w.ObservedAt)
	first, e2 := time.Parse(time.RFC3339, before.ObservedAt)
	last, e3 := time.Parse(time.RFC3339, after.ObservedAt)
	observed, e4 := time.Parse(time.RFC3339, observedAt)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || first.Before(at) || last.Before(first) || !last.Before(observed.Add(time.Second)) {
		return ErrUnavailable
	}
	return nil
}
