package plan

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestNotificationReadinessRequiresExactCanaryDeclaration(t *testing.T) {
	fixture := func() (generated.DeclarationRevision, []generated.PlanOperation) {
		return generated.DeclarationRevision{DeclarationType: "notification-readiness", Extensions: []generated.ContractExtension{{Name: "x-notification-readiness", ValueDigest: "policy"}, {Name: "x-credential-bindings", ValueDigest: "bindings"}}}, []generated.PlanOperation{{OperationID: "notification-readiness", OperationType: notificationReadinessOperation, AdapterID: "operations.notification-readiness", ArtifactDigest: "policy"}}
	}
	d, ops := fixture()
	if !notificationReadinessCandidate(d, ops) || !sealedNotificationReadiness(d, ops) {
		t.Fatal("exact canary denied")
	}
	for _, mutate := range []func(*generated.DeclarationRevision, *[]generated.PlanOperation){func(d *generated.DeclarationRevision, o *[]generated.PlanOperation) { d.DeclarationType = "arbitrary" }, func(d *generated.DeclarationRevision, o *[]generated.PlanOperation) { *o = append(*o, (*o)[0]) }, func(d *generated.DeclarationRevision, o *[]generated.PlanOperation) { (*o)[0].Idempotent = true }, func(d *generated.DeclarationRevision, o *[]generated.PlanOperation) { (*o)[0].AdapterID = "arbitrary" }, func(d *generated.DeclarationRevision, o *[]generated.PlanOperation) {
		d.Extensions[0].ValueDigest = "different"
	}, func(d *generated.DeclarationRevision, o *[]generated.PlanOperation) { d.Extensions = d.Extensions[:1] }} {
		d, ops := fixture()
		mutate(&d, &ops)
		if sealedNotificationReadiness(d, ops) {
			t.Fatal("changed canary accepted", d, ops)
		}
	}
}
