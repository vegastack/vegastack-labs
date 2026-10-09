package hostaction

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	protocol "github.com/vegastack/vegastack-labs/internal/hostaction"
)

func TestRecoveryReceiveRequiresBothCallbacksBeforeConnection(t *testing.T) {
	for _, configured := range []string{"neither", "source", "finalizer"} {
		t.Run(configured, func(t *testing.T) {
			a, op, binding, value, authority, target, connections := fixture(t, "success")
			original := a.bundles.(issuerFixture).envelope.Bundle
			original.ActionID = protocol.RecoveryReceiveAction
			raw, err := protocol.SignEnvelope(original, "key-a", authority.key)
			if err != nil {
				t.Fatal(err)
			}
			var envelope generated.HostActionEnvelope
			if json.Unmarshal(raw, &envelope) != nil {
				t.Fatal("envelope")
			}
			a.bundles = issuerFixture{envelope: envelope}
			called := false
			if configured == "source" {
				if a.SetRecoveryPayloadSource(func(context.Context, generated.HostActionBundle) (*RecoveryPayload, error) {
					called = true
					return nil, denied()
				}) != nil {
					t.Fatal("source")
				}
			}
			if configured == "finalizer" {
				if a.SetRecoveryReceiveFinalizer(func(context.Context, generated.HostActionBundle, generated.ControlRecoveryReceiveInput, generated.HostActionResult) error {
					called = true
					return nil
				}) != nil {
					t.Fatal("finalizer")
				}
			}
			effect, err := a.ExecuteBoundWithCredentials(context.Background(), op, binding, []*credentialref.Value{value})
			if err == nil || effect.EffectObserved || called || connections.Load() != 0 || target.calls != 0 || authority.calls != 0 {
				t.Fatal("incomplete receive composition reached transport")
			}
		})
	}
}
