package server

import (
	"context"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/result"
)

func TestOperationsFailClosedOnUnsupportedRuntimeBeforeConfigRead(t *testing.T) {
	operations := NewOperations(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-test", nil })
	err := operations.Run(context.Background(), "/private/config-canary-does-not-exist")
	stable, ok := failure.As(err)
	if !ok || stable.Code != generated.ErrorCodeUnsupportedPlatform {
		t.Fatalf("Run() error = %v", err)
	}
}
