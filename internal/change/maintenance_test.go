package change

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/maintenance"
	"testing"
	"time"
)

func TestMaintenanceIncidentRemainsInertAndBoundToNewRevision(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	q := generated.MaintenanceDraftRequest{Schema: generated.SchemaIDMaintenanceDraftRequest, SchemaVersion: "1.0.0", DeclarationID: "maintenance-a", ExpectedRevision: 2, ExpectedStateRevision: 4, RecoveryEpoch: 1, Action: "repair", TargetIDs: []string{"host-a"}, CanaryHostID: "host-a", ReasonDigest: hostaction.Digest("reason")}
	diagnosis := generated.MaintenanceDiagnosis{Schema: generated.SchemaIDMaintenanceDiagnosis, SchemaVersion: "1.0.0", HostID: "host-a", BindingDigest: hostaction.Digest("binding"), ObservationDigest: hostaction.Digest("observation"), Status: "unknown", StateRevision: 4, RecoveryEpoch: 1, ObservedAt: now.Format(time.RFC3339), NewAdmissionBlocked: true, ExistingWorkloads: "unchanged", Findings: []generated.MaintenanceFinding{}}
	record, e := maintenance.Prepare(q, []generated.MaintenanceDiagnosis{diagnosis}, "human-a", "session-a", now)
	if e != nil {
		t.Fatal(e)
	}
	draft, e := maintenance.Declaration(q, record)
	if e != nil {
		t.Fatal(e)
	}
	repo := &fakeRepository{}
	s, _ := NewService(repo, func() time.Time { return now })
	author := AuthorScope{PrincipalID: "human-a", PrincipalMethod: "local-os-peer", AgentSessionID: "session-a"}
	got, e := s.Revise(context.Background(), author, draft)
	if e != nil || got.Document.Status != "draft" || got.Document.Maintenance == nil || got.Document.Maintenance.ExecutionAvailable {
		t.Fatal(got, e)
	}
	original := got.Document.ContentDigest
	draft.Maintenance.Targets[0].BindingDigest = hostaction.Digest("changed")
	if _, e = s.Revise(context.Background(), author, draft); e == nil {
		t.Fatal("changed target bypassed sealed digest")
	}
	draft.Operations[0].InputDigest = hostaction.Digest(draft.Maintenance)
	draft.Operations[0].ArtifactDigest = draft.Operations[0].InputDigest
	draft.Extensions[0].ValueDigest = draft.Operations[0].InputDigest
	got, e = s.Revise(context.Background(), author, draft)
	if e != nil || got.Document.ContentDigest == original {
		t.Fatal("record omitted from canonical content", e)
	}
}
