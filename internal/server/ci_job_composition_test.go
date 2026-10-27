package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
)

func TestCIJobCannotCreateControlWithoutCurrentAuthority(t *testing.T) {
	f := ciJobControlFactory{}
	if _, e := f.NewCIControl(context.Background(), adapter.Operation{}, adapter.ExactExecutionBinding{}, nil); e == nil {
		t.Fatal("missing authority yielded a control peer")
	}
}
func TestCIJobSecretGateCannotFallBackToOrdinaryHostAction(t *testing.T) {
	g := hostActionGate{}
	if e := g.VerifySecretStep(context.Background(), generated.Plan{}, generated.PlanOperation{AdapterID: "host-action", OperationType: store.CIJobOperation}); e == nil {
		t.Fatal("CI missing policy reached fallback")
	}
}
