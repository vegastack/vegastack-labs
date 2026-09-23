package run

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type retirementExecutionFixture struct {
	digest string
	calls  int
}

func (f *retirementExecutionFixture) RetireOffsite(context.Context, adapter.Operation, adapter.ExactExecutionBinding, []*credentialref.Value) (string, error) {
	f.calls++
	return f.digest, nil
}
func (f *retirementExecutionFixture) VerifiedReceiptExists(_ context.Context, _ string, d string) (bool, error) {
	return d == f.digest, nil
}

func TestOffsiteRetirementEffectRequiresExactBoundHumanPlan(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	execution := &retirementExecutionFixture{digest: digest}
	effect, err := NewOffsiteRetirementEffect(execution)
	if err != nil {
		t.Fatal(err)
	}
	op := adapter.Operation{OperationID: "op", OperationType: "backup.retire.offsite", AdapterID: OffsiteRetirementAdapterID, ExecutorID: "central", TargetID: "intent-a", InputDigest: digest, ArtifactDigest: digest, SecretReferences: []adapter.SecretReference{{ID: "lock", Consumer: OffsiteRetirementAdapterID}, {ID: "retention", Consumer: OffsiteRetirementAdapterID}, {ID: "key", Consumer: OffsiteRetirementAdapterID}}}
	deadline := time.Now().UTC().Add(time.Minute).Format(time.RFC3339)
	binding := adapter.ExactExecutionBinding{PlanID: "plan", PlanDigest: digest, RunID: "run", StepID: "step", LeaseID: "lease", MaximumExpiresAt: deadline, ContractExtensions: []generated.ContractExtension{{Name: "x-backup-offsite-retirement", ValueDigest: digest}, {Name: "x-credential-bindings", ValueDigest: digest}}}
	lock, _ := credentialref.NewValue([]byte("lock"))
	retention, _ := credentialref.NewValue([]byte("retention"))
	key, _ := credentialref.NewValue([]byte("key"))
	defer lock.Close()
	defer retention.Close()
	defer key.Close()
	result, err := effect.ExecuteBoundWithCredentials(context.Background(), op, binding, []*credentialref.Value{lock, retention, key})
	if err != nil || !result.EffectObserved || execution.calls != 1 {
		t.Fatalf("result=%+v calls=%d err=%v", result, execution.calls, err)
	}
	if verified, err := effect.Verify(context.Background(), op, result); err != nil || !verified.Verified {
		t.Fatalf("verify=%+v err=%v", verified, err)
	}
	op.SecretReferences[1].ID = "lock"
	if _, err := effect.ExecuteBoundWithCredentials(context.Background(), op, binding, []*credentialref.Value{lock, retention, key}); err == nil {
		t.Fatal("same credential accepted")
	}
}
