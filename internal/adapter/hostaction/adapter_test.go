package hostaction

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"strings"
	"testing"
)

func TestUnboundExecutionDenied(t *testing.T) {
	var a Adapter
	if _, err := a.Execute(context.Background(), adapter.Operation{}); err == nil {
		t.Fatal("unbound execution accepted")
	}
	if _, err := New(nil, nil, nil); err == nil {
		t.Fatal("missing dependencies accepted")
	}
	if _, err := a.Verify(context.Background(), adapter.Operation{}, adapter.Effect{}); err == nil {
		t.Fatal("caller effect verified")
	}
}

func TestBoundExecutionRejectsBindingChangesBeforeConnection(t *testing.T) {
	for _, field := range []string{"plan", "digest", "run", "step", "lease", "revision", "epoch", "target", "reference", "root", "address", "uid", "identity"} {
		t.Run(field, func(t *testing.T) {
			a, op, b, v, _, target, connections := fixture(t, "success")
			switch field {
			case "plan":
				b.PlanID = "other"
			case "digest":
				b.PlanDigest = "sha256:" + strings.Repeat("b", 64)
			case "run":
				b.RunID = "other"
			case "step":
				b.StepID = "other"
			case "lease":
				b.LeaseID = "other"
			case "revision":
				b.StateRevision++
			case "epoch":
				b.RecoveryEpoch++
			case "target":
				op.TargetID = "other"
			case "reference":
				op.SecretReferences[0].ID = "other"
			case "root":
				target.target.User = "root"
			case "address":
				target.target.Address = "inventory-alias"
			case "uid":
				target.target.CallerUID++
			case "identity":
				target.target.HostIdentityDigest = "sha256:" + strings.Repeat("b", 64)
			}
			if _, err := a.ExecuteBoundWithCredentials(context.Background(), op, b, []*credentialref.Value{v}); err == nil {
				t.Fatal("changed binding accepted")
			}
			if connections.Load() != 0 {
				t.Fatal("invalid binding connected")
			}
		})
	}
}
func TestDiagnosticBudget(t *testing.T) {
	closed := false
	w := boundedDiscard{remaining: 3, close: func() error { closed = true; return nil }}
	if n, err := w.Write([]byte("abc")); err != nil || n != 3 {
		t.Fatal("valid bounded diagnostic denied")
	}
	if _, err := w.Write([]byte("x")); err == nil || !closed {
		t.Fatal("unbounded diagnostics accepted")
	}
}

func TestVerificationAcceptsEngineOperationWithoutJITReferences(t *testing.T) {
	a, op, b, v, _, _, _ := fixture(t, "success")
	effect, err := a.ExecuteBoundWithCredentials(context.Background(), op, b, []*credentialref.Value{v})
	if err != nil {
		t.Fatal(err)
	}
	op.SecretReferences = nil
	tampered := op
	tampered.InputDigest = "sha256:" + strings.Repeat("b", 64)
	if _, err = a.Verify(context.Background(), tampered, effect); err == nil {
		t.Fatal("changed sealed credential manifest verified")
	}
	verification, err := a.Verify(context.Background(), op, effect)
	if err != nil || !verification.Verified {
		t.Fatalf("engine verification failed: %v", err)
	}
	if _, err = a.Verify(context.Background(), op, effect); err == nil {
		t.Fatal("verification receipt reused")
	}
}
