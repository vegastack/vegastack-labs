package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/operations"
	"testing"
)

func TestNotificationCanaryCannotRunWithoutExactAcknowledgedSource(t *testing.T) {
	n := &notificationReadiness{}
	a, _ := credentialref.NewValue([]byte("seed-primary"))
	b, _ := credentialref.NewValue([]byte("https://hooks.slack.com/services/TSEED/BSEED/seed"))
	defer a.Close()
	defer b.Close()
	if _, e := n.Execute(context.Background(), adapter.Operation{}); e == nil {
		t.Fatal("unbound execution accepted")
	}
	op := adapter.Operation{AdapterID: operations.ReadinessAdapter, OperationType: operations.ReadinessOperation, SecretReferences: []adapter.SecretReference{{ID: "primary", Consumer: operations.ReadinessAdapter}, {ID: "secondary", Consumer: operations.ReadinessAdapter}}}
	if _, e := n.ExecuteBoundWithCredentials(context.Background(), op, adapter.ExactExecutionBinding{}, []*credentialref.Value{a, b}); e == nil {
		t.Fatal("values without current approved source permitted sends")
	}
	n.results = map[string]adapter.ExactExecutionBinding{}
	if _, e := n.Verify(context.Background(), op, adapter.Effect{Status: "succeeded", ResultDigest: operations.Digest("uploaded-claim")}); e == nil {
		t.Fatal("caller assertion promoted to verified receipt")
	}
	if _, e := n.prepare(context.Background(), generated.NotificationReadinessRequest{}); e == nil {
		t.Fatal("unselected policy prepared live evidence")
	}
}
