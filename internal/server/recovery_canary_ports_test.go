package server

import (
	"context"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/recovery"
)

type qualifiedCanaryCapabilities struct{}

func (qualifiedCanaryCapabilities) AppendRecoveryCheckpoint(context.Context, recovery.CanaryRequest, string) (string, error) {
	return "checkpoint-a", nil
}
func (qualifiedCanaryCapabilities) CreateRecoveryBackup(context.Context, recovery.CanaryRequest) (string, string, error) {
	return "point-a", "standard", nil
}

func TestQualifiedRecoveryCanaryFactoryRejectsMissingCapabilities(t *testing.T) {
	if _, err := NewQualifiedRecoveryCanaryPortFactory(nil, qualifiedCanaryCapabilities{}); stableCode(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("missing checkpoint capability err = %v", err)
	}
	if _, err := NewQualifiedRecoveryCanaryPortFactory(qualifiedCanaryCapabilities{}, nil); stableCode(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("missing backup capability err = %v", err)
	}
	if factory, err := NewQualifiedRecoveryCanaryPortFactory(qualifiedCanaryCapabilities{}, qualifiedCanaryCapabilities{}); err != nil || factory == nil {
		t.Fatalf("factory = %v, err = %v", factory, err)
	}
}
