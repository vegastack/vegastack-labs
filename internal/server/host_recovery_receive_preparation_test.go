package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
)

func TestRecoveryReceivePreparationDoesNotTrustCallerDescriptor(t *testing.T) {
	input := generated.HostActionRequest{ActionID: store.ControlRecoveryReceiveAction, ActionInput: `{"binding":{"planId":"caller-selected"},"candidateBytesDigest":"` + hostaction.Digest("caller") + `"}`}
	if _, err := (hostRecoveryReceivePreparation{}).PrepareRecoveryReceive(context.Background(), input); err == nil {
		t.Fatal("caller descriptor granted transfer authority")
	}
}
