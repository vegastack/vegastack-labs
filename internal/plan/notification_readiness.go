package plan

import "github.com/vegastack/vegastack-labs/internal/generated"

const notificationReadinessOperation = "operations.notification-readiness.test"

func notificationReadinessCandidate(d generated.DeclarationRevision, ops []generated.PlanOperation) bool {
	if d.DeclarationType == "notification-readiness" {
		return true
	}
	for _, o := range ops {
		if o.OperationType == notificationReadinessOperation || o.AdapterID == "operations.notification-readiness" {
			return true
		}
	}
	for _, x := range d.Extensions {
		if x.Name == "x-notification-readiness" {
			return true
		}
	}
	return false
}
func sealedNotificationReadiness(d generated.DeclarationRevision, ops []generated.PlanOperation) bool {
	if d.DeclarationType != "notification-readiness" || len(ops) != 1 {
		return false
	}
	o := ops[0]
	if o.OperationID != "notification-readiness" || o.OperationType != notificationReadinessOperation || o.AdapterID != "operations.notification-readiness" || o.Idempotent {
		return false
	}
	policy, bindings := false, false
	for _, x := range d.Extensions {
		switch x.Name {
		case "x-notification-readiness":
			policy = x.ValueDigest == o.ArtifactDigest
		case "x-credential-bindings":
			bindings = x.ValueDigest != ""
		}
	}
	return policy && bindings
}
