package runprotocol

import "testing"

func TestIDIsStableAndSeparatesInputs(t *testing.T) {
	if got, want := ID("plan-1", "key-1"), "run-f0275f3f6438a625ef38332d09f488c6"; got != want {
		t.Fatalf("ID() = %q, want %q", got, want)
	}
	if ID("plan-1", "key-2") == ID("plan-2", "key-1") {
		t.Fatal("different bindings produced the same run ID")
	}
}
