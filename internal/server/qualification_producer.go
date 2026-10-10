package server

import (
	"context"
	transport "github.com/vegastack/vegastack-labs/internal/adapter/hostaction"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/qualification"
	"time"
)

// The read-only wrapper exports the already completed adapter bundle only for
// the two protocol scenarios whose independent target witness requires it.
// Store execution/reference authority and native proof collection are unchanged.
func (s *nativeQualificationService) LookupNativeProducerData(ctx context.Context, in generated.NativeProducerLookupRequest) (generated.NativeProducerLookupData, error) {
	var zero generated.NativeProducerLookupData
	ref, bundleDigest, receiptDigest, err := s.lookupNativeProducer(ctx, in)
	if err != nil {
		return zero, err
	}
	out := generated.NativeProducerLookupData{Schema: generated.SchemaIDNativeProducerLookupData, SchemaVersion: "1.0.0", ProducerReference: ref, ReceiptDigest: receiptDigest}
	if in.ScenarioID != "action-replay" && in.ScenarioID != "action-concurrency" {
		return out, nil
	}
	deny := func() (generated.NativeProducerLookupData, error) {
		return zero, failure.New(generated.ErrorCodePrerequisiteBlocked, "native-producer-bundle", false)
	}
	if s.adapters == nil {
		return deny()
	}
	implementation, err := s.adapters.Resolve("host-action")
	actual, ok := implementation.(*transport.Adapter)
	if err != nil || !ok {
		return deny()
	}
	// Use only an existing in-memory completed observation, with the exact
	// durable lease resolved by the current scoped reference read.
	witness, err := actual.NativeProtocolObservationForExecution(bundleDigest, ref.RunID, ref.StepID, ref.LeaseID)
	if err != nil {
		return deny()
	}
	bundle, err := nativeProducerBundle(in, ref, witness)
	if err != nil {
		return deny()
	}
	// Recheck the protected immutable window immediately before exporting; a
	// successful earlier database read cannot extend its fixture authority.
	scope, err := qualification.LoadServerScope(ctx)
	issued, e1 := time.Parse(time.RFC3339, scope.IssuedAt)
	expires, e2 := time.Parse(time.RFC3339, scope.ExpiresAt)
	at := time.Now().UTC()
	if err != nil || e1 != nil || e2 != nil || hostaction.Digest(scope) != in.ScopeDigest || at.Before(issued) || !at.Before(expires) {
		return deny()
	}
	out.ActionBundle = &bundle
	return out, nil
}

func nativeProducerBundle(in generated.NativeProducerLookupRequest, ref generated.NativeProducerReference, w generated.NativeActionProtocolWitness) (generated.HostActionBundle, error) {
	if w.ScenarioID != in.ScenarioID || w.CompletedResults != 1 || w.ResultDigest == "" || !hostaction.NativeProducerBundleMatches(in, ref, w.Bundle) {
		return generated.HostActionBundle{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "native-producer-bundle", false)
	}
	return w.Bundle, nil
}

// Lookup returns an existing terminal execution reference. It performs no
// native observation, evidence creation or qualification transition.
func (s *nativeQualificationService) lookupNativeProducer(ctx context.Context, in generated.NativeProducerLookupRequest) (generated.NativeProducerReference, string, string, error) {
	var zero generated.NativeProducerReference
	deny := func() (generated.NativeProducerReference, string, string, error) {
		return zero, "", "", failure.New(generated.ErrorCodePrerequisiteBlocked, "native-producer", false)
	}
	if s == nil || s.gates == nil || s.authority == nil {
		return deny()
	}
	scope, err := qualification.LoadServerScope(ctx)
	if err != nil || hostaction.Digest(scope) != in.ScopeDigest {
		return deny()
	}
	found := false
	for _, g := range scope.Guests {
		if g.HostID == in.HostID {
			found = true
		}
	}
	if !found {
		return deny()
	}
	gates := s.gates
	if in.ScenarioID == "native-credential-lifecycle" {
		authority, err := s.authority.CurrentAuthority(ctx)
		if err != nil {
			return deny()
		}
		measured, err := qualification.MeasureControllerIdentity(ctx, scope, authority.InstanceID)
		if err != nil {
			return deny()
		}
		gates = gates.WithNativeControllerIdentity(measured)
	}
	return gates.LookupNativeProducerDataBindings(ctx, in, scope)
}
