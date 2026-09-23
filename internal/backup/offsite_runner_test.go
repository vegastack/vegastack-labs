package backup

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

type revisionBindingSpecs struct {
	declaration OffsiteRunDeclaration
	policy      OffsitePolicy
	prepared    bool
}

func (source *revisionBindingSpecs) ResolveOffsiteDeclaration(context.Context, adapter.Operation, adapter.ExactExecutionBinding) (OffsiteRunDeclaration, OffsitePolicy, error) {
	return source.declaration, source.policy, nil
}
func (source *revisionBindingSpecs) PrepareOffsiteRun(context.Context, OffsiteRunDeclaration, adapter.Operation, adapter.ExactExecutionBinding, []*credentialref.Value) (OffsiteRunSpec, error) {
	source.prepared = true
	return OffsiteRunSpec{}, errors.New("unexpected runtime preparation")
}

type unusedOffsiteCatalog struct{}

func (unusedOffsiteCatalog) AppendPending(context.Context, PendingOffsiteGeneration) error {
	return nil
}
func (unusedOffsiteCatalog) GetGeneration(context.Context, string) (PendingOffsiteGeneration, error) {
	return PendingOffsiteGeneration{}, errors.New("unused")
}
func (unusedOffsiteCatalog) AppendProof(context.Context, OffsiteProof) error { return nil }
func (unusedOffsiteCatalog) ProofExists(context.Context, string, string) (bool, error) {
	return false, nil
}
func (unusedOffsiteCatalog) AdvanceLastGood(context.Context, OffsiteProof, int64) error { return nil }
func (unusedOffsiteCatalog) Status(context.Context, string) (OffsiteStatus, error) {
	return OffsiteStatus{}, errors.New("unused")
}

func TestOffsiteRunnerRejectsInternallyConsistentFalseDeclaredSourceRevisionBeforeRuntime(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	point := testVerifiedCriticalPoint(now)
	policy := testOffsitePolicy(now)
	specs := &revisionBindingSpecs{declaration: OffsiteRunDeclaration{GenerationID: policy.GenerationID, SourcePointID: point.PointID, SourceRevision: point.SourceRevision + 1}, policy: policy}
	runner, err := NewOffsiteWorkflowRunner(fakeOffsiteSource{point: point}, specs, unusedOffsiteCatalog{})
	if err != nil {
		t.Fatal(err)
	}
	values := make([]*credentialref.Value, 3)
	for index := range values {
		values[index], _ = credentialref.NewValue([]byte("fixture-secret"))
		defer values[index].Close()
	}
	operation := adapter.Operation{TargetID: policy.GenerationID}
	binding := adapter.ExactExecutionBinding{StateRevision: point.StateRevision, RecoveryEpoch: point.RecoveryEpoch}
	if _, err := runner.CopyAndVerify(context.Background(), operation, binding, values); err == nil {
		t.Fatal("false declared source revision reached runtime")
	}
	if specs.prepared {
		t.Fatal("runtime/custody prepared before authoritative source revision comparison")
	}
}
