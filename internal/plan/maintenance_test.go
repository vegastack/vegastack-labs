package plan

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
	"time"
)

func TestMaintenanceReviewCannotAcquireExecutionPlan(t *testing.T) {
	for _, kind := range []string{"payload", "type", "adapter", "operation"} {
		d := validDeclaration()
		switch kind {
		case "payload":
			d.Maintenance = &generated.MaintenanceRecord{}
		case "type":
			d.DeclarationType = "maintenance.review"
		case "adapter":
			d.Operations[0].AdapterID = "local.maintenance.unsupported"
		case "operation":
			d.Operations[0].OperationType = "maintenance.review"
		}
		repo := &fakePlanRepository{declaration: d, current: store.RevisionToken{StateRevision: 9, RecoveryEpoch: 2}}
		observations := &fakeObservations{fingerprint: testDigestString("b")}
		s := newTestService(t, repo, observations, time.Now)
		if _, e := s.Prepare(context.Background(), d.DeclarationID, d.Revision); planFailureCode(e) != generated.ErrorCodePrerequisiteBlocked {
			t.Fatal(kind, e)
		}
		if _, e := s.Create(context.Background(), AuthorScope{PrincipalID: "principal-test", PrincipalMethod: "local-os-peer"}, validRequest()); planFailureCode(e) != generated.ErrorCodePrerequisiteBlocked {
			t.Fatal(kind, e)
		}
	}
}
