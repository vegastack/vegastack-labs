package run

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type offsiteExecutionFixture struct{ calls int }

func (fixture *offsiteExecutionFixture) CopyAndVerify(ctx context.Context, operation adapter.Operation, binding adapter.ExactExecutionBinding, values []*credentialref.Value) (backup.OffsiteProof, error) {
	return fixture.ExecuteOffsite(ctx, operation, binding, values)
}

func (fixture *offsiteExecutionFixture) ExecuteOffsite(_ context.Context, operation adapter.Operation, binding adapter.ExactExecutionBinding, _ []*credentialref.Value) (backup.OffsiteProof, error) {
	fixture.calls++
	return backup.OffsiteProof{ProofID: "proof-a", ProofDigest: operation.ArtifactDigest, Status: backup.OffsiteStatusVerified, ProofClass: backup.OffsiteProofQualified, GenerationID: operation.TargetID, RecoveryEpoch: binding.RecoveryEpoch}, nil
}
func (*offsiteExecutionFixture) ProofExists(context.Context, string, string) (bool, error) {
	return true, nil
}

func TestOffsiteEffectRequiresEnabledExecutionAndExactBoundApprovalInputs(t *testing.T) {
	if _, err := NewOffsiteEffect(nil); err == nil {
		t.Fatal("unqualified offsite execution enabled")
	}
	fixture := &offsiteExecutionFixture{}
	effect, err := NewOffsiteEffect(fixture)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	operation := adapter.Operation{OperationID: "offsite-copy-a", OperationType: "backup.offsite.copy", AdapterID: OffsiteAdapterID, ExecutorID: "executor-central", TargetID: "generation-a", InputDigest: digest, ArtifactDigest: digest, SecretReferences: []adapter.SecretReference{{ID: "parent-a", Consumer: OffsiteAdapterID}, {ID: "password-a", Consumer: OffsiteAdapterID}, {ID: "observer-a", Consumer: OffsiteAdapterID}}}
	value, err := credentialref.NewValue([]byte("borrowed-parent-material"))
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()
	password, err := credentialref.NewValue([]byte("borrowed-repository-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer password.Close()
	observer, err := credentialref.NewValue([]byte("borrowed-read-only-observer"))
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	values := []*credentialref.Value{value, password, observer}
	binding := adapter.ExactExecutionBinding{PlanID: "plan-a", PlanDigest: digest, RunID: "run-a", StepID: "step-a", LeaseID: "lease-a", StateRevision: 7, RecoveryEpoch: 3, MaximumExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), ContractExtensions: []generated.ContractExtension{{Name: "x-offsite-generation", ValueDigest: digest}, {Name: "x-credential-bindings", ValueDigest: digest}}}
	for name, mutate := range map[string]func(*adapter.ExactExecutionBinding){
		"missing-plan": func(value *adapter.ExactExecutionBinding) { value.PlanID = "" },
		"expired": func(value *adapter.ExactExecutionBinding) {
			value.MaximumExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
		},
		"wrong-generation-digest": func(value *adapter.ExactExecutionBinding) {
			value.ContractExtensions[0].ValueDigest = "sha256:" + strings.Repeat("b", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := binding
			candidate.ContractExtensions = append([]generated.ContractExtension(nil), binding.ContractExtensions...)
			mutate(&candidate)
			if _, err := effect.ExecuteBoundWithCredentials(context.Background(), operation, candidate, values); err == nil {
				t.Fatal("inexact offsite effect executed")
			}
		})
	}
	result, err := effect.ExecuteBoundWithCredentials(context.Background(), operation, binding, values)
	if err != nil || fixture.calls != 1 || !result.Changed || result.PendingPointID == nil || *result.PendingPointID != operation.TargetID {
		t.Fatalf("result=%#v calls=%d err=%v", result, fixture.calls, err)
	}
}

func TestCatalogOffsiteExecutionRequiresRunnerAndDurableCatalog(t *testing.T) {
	fixture := &offsiteExecutionFixture{}
	if _, err := NewCatalogOffsiteExecution(nil, fixture); err == nil {
		t.Fatal("missing runner admitted")
	}
	if _, err := NewCatalogOffsiteExecution(fixture, nil); err == nil {
		t.Fatal("missing catalog admitted")
	}
	execution, err := NewCatalogOffsiteExecution(fixture, fixture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewOffsiteEffect(execution); err != nil {
		t.Fatalf("qualified concrete execution not registrable: %v", err)
	}
}
