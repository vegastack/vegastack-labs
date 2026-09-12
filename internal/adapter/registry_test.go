package adapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"sort"
	"testing"
)

func TestRegistryRejectsUnknownAndWidenedOperations(t *testing.T) {
	registry := NewRegistry()
	if _, err := registry.Resolve("test.fake"); Code(err) != "PREREQUISITE_BLOCKED" {
		t.Fatalf("production fake code = %q", Code(err))
	}
	operation := Operation{OperationID: "operation-test", OperationType: "application.deploy.low-risk", AdapterID: "adapter-test", ExecutorID: "executor-central", TargetID: "target-test", InputDigest: testDigest("input"), ArtifactDigest: testDigest("artifact"), Idempotent: true}
	if err := ValidateOperation(operation); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Operation{
		func() Operation { value := operation; value.TargetID = "https://attacker.invalid"; return value }(),
		func() Operation { value := operation; value.OperationType = "sh -c"; return value }(),
		func() Operation {
			value := operation
			value.SecretReferences = []SecretReference{{ID: "secret-test", Consumer: "other-adapter"}}
			return value
		}(),
	} {
		if err := ValidateOperation(bad); Code(err) != "INPUT_INVALID" && Code(err) != "AUTHORIZATION_DENIED" {
			t.Fatalf("bad operation code = %q for %#v", Code(err), bad)
		}
	}
	fixture := &recordingAdapter{}
	if err := registry.Register("adapter-test", fixture); err != nil {
		t.Fatal(err)
	}
	resolved, err := registry.Resolve("adapter-test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolved.Execute(context.Background(), operation); err != nil {
		t.Fatal(err)
	}
}

func TestAdapterOperationSurfaceStaysClosedAndSecretValueFree(t *testing.T) {
	assertFields := func(value any, expected []string) {
		t.Helper()
		typeOf := reflect.TypeOf(value)
		actual := make([]string, typeOf.NumField())
		for index := range typeOf.NumField() {
			actual[index] = typeOf.Field(index).Name
		}
		sort.Strings(actual)
		sort.Strings(expected)
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("%s fields widened: got %v want %v", typeOf.Name(), actual, expected)
		}
	}
	assertFields(Operation{}, []string{"AdapterID", "ArtifactDigest", "ExecutorID", "Idempotent", "InputDigest", "OperationID", "OperationType", "SecretReferences", "TargetID"})
	assertFields(SecretReference{}, []string{"Consumer", "ID"})
	assertFields(Effect{}, []string{"Changed", "EffectObserved", "ResultDigest", "Status"})
	assertFields(Verification{}, []string{"Digest", "Verified"})
}

type recordingAdapter struct{}

func (*recordingAdapter) Execute(context.Context, Operation) (Effect, error) {
	return Effect{Status: "succeeded", ResultDigest: testDigest("result"), Changed: true, EffectObserved: true}, nil
}
func (*recordingAdapter) Verify(context.Context, Operation, Effect) (Verification, error) {
	return Verification{Verified: true, Digest: testDigest("verify")}, nil
}

func testDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
