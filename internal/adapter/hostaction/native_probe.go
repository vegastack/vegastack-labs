package hostaction

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	protocol "github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/qualification"
	"time"
)

func (a *Adapter) exchange(ctx context.Context, target Target, envelope generated.HostActionEnvelope, digest string, value *credentialref.Value) (generated.HostActionResult, bool, error) {
	scenario, err := qualification.NativeTransportProbe(ctx, envelope.Bundle)
	if err != nil {
		return generated.HostActionResult{}, false, err
	}
	if scenario == "" {
		return a.exchangeOne(ctx, target, envelope, digest, value, nil, nil, nil, "")
	}
	return a.exchangeNativeProbe(ctx, target, envelope, digest, value, scenario)
}

func (a *Adapter) exchangeNativeProbe(ctx context.Context, target Target, envelope generated.HostActionEnvelope, digest string, value *credentialref.Value, scenario string) (generated.HostActionResult, bool, error) {
	if envelope.Bundle.ActionID != "debian.access.collect" || (scenario != "action-replay" && scenario != "action-concurrency") {
		return generated.HostActionResult{}, false, denied()
	}
	type outcome struct {
		result   generated.HostActionResult
		observed bool
		refusal  generated.HostActionDenial
		err      error
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	count := 1
	if scenario == "action-concurrency" {
		count = 3
	}
	ready := make(chan struct{}, count)
	release := make(chan struct{})
	finished := make(chan outcome, count)
	for i := 0; i < count; i++ {
		go func() {
			var out outcome
			out.result, out.observed, out.err = a.exchangeOne(ctx, target, envelope, digest, value, ready, release, &out.refusal, "")
			finished <- out
		}()
	}
	timer := time.NewTimer(4 * time.Second)
	defer timer.Stop()
	for n := 0; n < count; n++ {
		select {
		case <-ready:
		case <-finished:
			cancel()
			return generated.HostActionResult{}, true, denied()
		case <-timer.C:
			cancel()
			return generated.HostActionResult{}, true, denied()
		case <-ctx.Done():
			return generated.HostActionResult{}, true, ctx.Err()
		}
	}
	close(release)
	measured := generated.NativeActionProtocolWitness{Schema: generated.SchemaIDNativeActionProtocolWitness, SchemaVersion: "1.0.0", NegativeAttempts: []generated.NativeActionNegativeObservation{}, Bundle: envelope.Bundle, ScenarioID: scenario, ConcurrentAttempts: int64(count), ConcurrentDenials: []generated.HostActionDenial{}}
	var winner generated.HostActionResult
	for n := 0; n < count; n++ {
		select {
		case out := <-finished:
			if out.err != nil {
				return generated.HostActionResult{}, true, out.err
			}
			if out.refusal.Phase != "" {
				measured.ConcurrentDenials = append(measured.ConcurrentDenials, out.refusal)
			} else {
				measured.CompletedResults++
				winner = out.result
			}
		case <-ctx.Done():
			return generated.HostActionResult{}, true, ctx.Err()
		}
	}
	if measured.CompletedResults != 1 || len(measured.ConcurrentDenials) != count-1 {
		return generated.HostActionResult{}, true, denied()
	}
	_, observed, err := a.exchangeOne(ctx, target, envelope, digest, value, nil, nil, &measured.ReplayDenial, "")
	if err != nil || observed || measured.ReplayDenial.Phase != "execution-claim" {
		return generated.HostActionResult{}, true, denied()
	}
	for _, variant := range []string{"malformed-envelope", "wrong-host", "wrong-plan", "wrong-epoch", "invalid-signature"} {
		attempt := generated.NativeActionNegativeObservation{Schema: generated.SchemaIDNativeActionNegativeObservation, SchemaVersion: "1.0.0", Variant: variant}
		_, observed, e := a.exchangeOne(ctx, target, envelope, digest, value, nil, nil, &attempt.Denial, variant)
		if e != nil || observed || attempt.Denial.Phase != "envelope" {
			return generated.HostActionResult{}, true, denied()
		}
		measured.NegativeAttempts = append(measured.NegativeAttempts, attempt)
	}
	_, observed, err = a.exchangeOne(ctx, target, envelope, digest, value, nil, nil, &measured.ReplayAfterDenial, "")
	if err != nil || observed || measured.ReplayDenial.ClaimDigest == "" || measured.ReplayDenial.ResultDigest != protocol.Digest(winner) || measured.ReplayAfterDenial.ClaimDigest != measured.ReplayDenial.ClaimDigest || measured.ReplayAfterDenial.ResultDigest != measured.ReplayDenial.ResultDigest {
		return generated.HostActionResult{}, true, denied()
	}
	measured.ResultDigest = protocol.Digest(winner)
	measured.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.nativeProtocol == nil {
		a.nativeProtocol = map[string]generated.NativeActionProtocolWitness{}
	}
	key := protocol.ExecutionDigest(envelope.Bundle)
	if _, exists := a.nativeProtocol[key]; exists || len(a.nativeProtocol) >= 48 {
		return generated.HostActionResult{}, true, denied()
	}
	a.nativeProtocol[key] = measured
	return winner, true, nil
}

// NativeProtocolObservationFor returns only a matching observation produced by
// this live adapter. Callers must additionally verify the durable product run
// and dedicated native target observation; this getter confers no authority.
func (a *Adapter) NativeProtocolObservationFor(bundle generated.HostActionBundle) (generated.NativeActionProtocolWitness, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out, ok := a.nativeProtocol[protocol.ExecutionDigest(bundle)]
	if !ok || protocol.Digest(out.Bundle) != protocol.Digest(bundle) {
		return generated.NativeActionProtocolWitness{}, denied()
	}
	return out, nil
}

func (a *Adapter) NativeProtocolObservationForExecution(bundleDigest, runID, stepID, leaseID string) (generated.NativeActionProtocolWitness, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, out := range a.nativeProtocol {
		d, e := protocol.BundleDigest(out.Bundle)
		if e == nil && d == bundleDigest && out.Bundle.RunID == runID && out.Bundle.StepID == stepID && out.Bundle.LeaseID == leaseID {
			return out, nil
		}
	}
	return generated.NativeActionProtocolWitness{}, denied()
}
