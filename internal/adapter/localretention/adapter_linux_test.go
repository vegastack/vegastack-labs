//go:build linux

package localretention

import (
	"context"
	"math"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/backup"
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

func TestMeasuredRetirementBytesRejectInvalidInventory(t *testing.T) {
	if got, ok := inventoryBytes([]backup.ExpectedObject{{Bytes: 5}, {Bytes: 7}}); !ok || got != 12 {
		t.Fatalf("bounded inventory bytes=%d ok=%t", got, ok)
	}
	for _, objects := range [][]backup.ExpectedObject{{{Bytes: -1}}, {{Bytes: math.MaxInt64}, {Bytes: 1}}} {
		if _, ok := inventoryBytes(objects); ok {
			t.Fatal("invalid inventory bytes accepted")
		}
	}
}

func TestLocalRetentionRequiresServerOwnedRepositories(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("local retention constructed without server-owned repositories")
	}
}
