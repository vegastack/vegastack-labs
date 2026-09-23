//go:build linux

package localretention

import (
	"context"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter"
)

func TestLocalRetentionHasNoUnboundExecutionPath(t *testing.T) {
	instance := &Adapter{}
	if _, err := instance.Execute(context.Background(), adapter.Operation{}); err == nil {
		t.Fatal("plain execution admitted destructive local retention")
	}
	if _, err := instance.ExecuteWithCredentials(context.Background(), adapter.Operation{}, nil); err == nil {
		t.Fatal("credential-only execution admitted destructive local retention")
	}
	if _, err := instance.ExecuteBoundWithCredentials(context.Background(), adapter.Operation{}, adapter.ExactExecutionBinding{}, nil); err == nil {
		t.Fatal("malformed exact binding admitted destructive local retention")
	}
}

func TestLocalRetentionRequiresServerOwnedRepositories(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("local retention constructed without server-owned repositories")
	}
}
