package server

import (
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestProductionAdapterRegistryCannotResolveTestFake(t *testing.T) {
	registry := adapter.NewRegistry()
	if _, err := registry.Resolve("test.fake"); adapter.Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("fake adapter resolution code = %q", adapter.Code(err))
	}
}
