package run

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"testing"
)

func TestDiscoveryTargetEffectRejectsMissingBinding(t *testing.T) {
	effect := &HostDiscoveryTargetEffect{}
	if _, err := effect.Execute(context.Background(), ExactStepBinding{}); err == nil {
		t.Fatal("unbound execution allowed")
	}
	if _, err := effect.Verify(context.Background(), ExactStepBinding{}, adapter.Effect{}); err == nil {
		t.Fatal("unbound verification allowed")
	}
}
