//go:build linux

package server

import (
	"context"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
)

func TestProductionCredentialFoundationRemainsDormant(t *testing.T) {
	registry := productionAdapterRegistry()
	if _, err := registry.ResolveCredentialResolver("onepassword", "consumer-a", "profile-a"); adapter.Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("production resolver registered: %v", err)
	}
	if err := (runengine.UnavailableGateVerifier{}).VerifySecretStep(context.Background(), generated.Plan{}, generated.PlanOperation{}); runengine.Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("production secret gate admitted: %v", err)
	}
}
