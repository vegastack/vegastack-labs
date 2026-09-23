package server

import (
	"context"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type retirementSourceFixture struct {
	qualified bool
	execution runengine.OffsiteRetirementExecution
}

func (f retirementSourceFixture) Execution(context.Context, serverconfig.Profile, *store.Store) (runengine.OffsiteRetirementExecution, bool, error) {
	return f.execution, f.qualified, nil
}

type retirementExecutionServerFixture struct{}

func (retirementExecutionServerFixture) RetireOffsite(context.Context, adapter.Operation, adapter.ExactExecutionBinding, []*credentialref.Value) (string, error) {
	return "", nil
}
func (retirementExecutionServerFixture) VerifiedReceiptExists(context.Context, string, string) (bool, error) {
	return false, nil
}

func TestRetirementCompositionAndRegistrationFailClosed(t *testing.T) {
	profile := serverconfig.Profile{OffsiteBackup: &serverconfig.OffsiteBackup{}}
	for _, qualified := range []bool{false, true} {
		factory := NewProductionOffsiteRetirementEffectFactory(retirementSourceFixture{qualified: qualified, execution: retirementExecutionServerFixture{}})
		effect, err := factory(context.Background(), profile, &store.Store{})
		if err != nil {
			t.Fatal(err)
		}
		registry := adapter.NewRegistry()
		if err := registerOffsiteRetirementEffect(registry, profile.OffsiteBackup, effect); err != nil {
			t.Fatal(err)
		}
		_, resolveErr := registry.Resolve(runengine.OffsiteRetirementAdapterID)
		if qualified == (resolveErr != nil) {
			t.Fatalf("qualified=%v resolve=%v", qualified, resolveErr)
		}
	}
}
