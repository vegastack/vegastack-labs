package server

import (
	"context"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

type offsiteAdapterFixture struct{}

func (offsiteAdapterFixture) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	return adapter.Effect{}, nil
}
func (offsiteAdapterFixture) Verify(context.Context, adapter.Operation, adapter.Effect) (adapter.Verification, error) {
	return adapter.Verification{}, nil
}

func TestOffsiteAdapterRegistersOnlyWithProfileAndQualifiedEffect(t *testing.T) {
	registry := adapter.NewRegistry()
	if err := registerOffsiteEffect(registry, nil, offsiteAdapterFixture{}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Resolve("labs.r2-offsite"); err == nil {
		t.Fatal("offsite adapter registered without profile")
	}
	profile := &serverconfig.OffsiteBackup{Endpoint: "https://fixture.invalid", Bucket: "bucket-a", Prefix: "critical", ParentReferenceID: "parent-a"}
	if err := registerOffsiteEffect(registry, profile, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Resolve("labs.r2-offsite"); err == nil {
		t.Fatal("offsite adapter registered without qualified effect")
	}
	if err := registerOffsiteEffect(registry, profile, offsiteAdapterFixture{}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Resolve("labs.r2-offsite"); err != nil {
		t.Fatalf("qualified adapter unavailable: %v", err)
	}
}
