package server

import (
	"context"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type qualifiedCanaryCapabilities struct{}

func (qualifiedCanaryCapabilities) ProduceRecoveryCheckpoint(context.Context, recovery.CanaryRequest, string) (store.RecoveryCanaryCheckpointRecord, error) {
	return store.RecoveryCanaryCheckpointRecord{Checkpoint: generated.AuditCheckpoint{CheckpointID: "checkpoint-a"}}, nil
}

func TestQualifiedRecoveryCanaryFactoryRejectsMissingCapabilities(t *testing.T) {
	if _, err := NewQualifiedRecoveryCanaryPortFactory(nil); stableCode(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("missing checkpoint capability err = %v", err)
	}
	if factory, err := NewQualifiedRecoveryCanaryPortFactory(qualifiedCanaryCapabilities{}); err != nil || factory == nil {
		t.Fatalf("factory = %v, err = %v", factory, err)
	}
}
