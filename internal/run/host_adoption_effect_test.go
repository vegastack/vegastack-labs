package run

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"testing"
)

func TestHostAdoptionEffectRejectsMissingConfiguration(t *testing.T) {
	e := &HostAdoptionEffect{}
	if _, err := e.Execute(context.Background(), ExactStepBinding{}); err == nil {
		t.Fatal("missing config accepted")
	}
	if _, err := e.Verify(context.Background(), ExactStepBinding{}, adapter.Effect{}); err == nil {
		t.Fatal("missing config verified")
	}
}
