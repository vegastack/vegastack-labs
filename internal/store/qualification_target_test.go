package store

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"testing"
)

func TestQualificationTargetRequiresActualAcknowledgedActivationWithoutMutation(t *testing.T) {
	f := newRegistrationStoreFixture(t)
	d := hostdiscovery.Digest("fixture")
	scope := generated.QualificationScope{Schema: generated.SchemaIDQualificationScope, SchemaVersion: "1.0.0", RunID: "native-a", Purpose: "native-debian", ControllerInstanceID: "controller-database", ControlServiceUID: 1001, ControlServiceGID: 1001, PhysicalHostID: "synthetic-host", PhysicalHostBootID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", PhysicalHostIdentityDigest: f.request.Confirmation.IdentityDigest, SourceCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExecutableDigest: d, ImageDigest: d, ProfileID: "profile-a", ProfileLockDigest: d, ConsoleReferenceDigest: d, OutputRoot: "/owned", MaximumDurationSeconds: 3600, IssuedAt: "2026-10-09T00:00:00Z", ExpiresAt: "2026-10-09T01:00:00Z", Resources: generated.QualificationResources{Schema: generated.SchemaIDQualificationResources, SchemaVersion: "1.0.0", CPUs: 6, MemoryBytes: 8589934592, StorageBytes: 85899345920}, Guests: []generated.QualificationGuest{{Schema: generated.SchemaIDQualificationGuest, SchemaVersion: "1.0.0", GuestID: "guest-a", HostID: "host-a", HostIdentityDigest: d, InstanceID: "instance-a", SSHHostKeyDigest: d, Role: "controller", SnapshotID: "clean", DiskDigest: d, FirmwareDigest: d, CPUs: 1, MemoryBytes: 1073741824, DiskBytes: 3221225472}}}
	subject := scope.Guests[0]
	subject.GuestID, subject.HostID, subject.InstanceID, subject.Role = "guest-b", "host-b", "instance-b", "subject"
	subject.HostIdentityDigest, subject.SSHHostKeyDigest = hostdiscovery.Digest("subject-identity"), hostdiscovery.Digest("subject-key")
	scope.Guests = append(scope.Guests, subject)
	current, err := NewPlanRepository(f.s).CurrentRevision(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	in := generated.QualificationInspectRequest{Schema: generated.SchemaIDQualificationInspectRequest, SchemaVersion: "1.0.0", TargetID: "candidate-a", TargetRevision: 1, TargetDigest: f.request.Confirmation.TargetDigest, Scope: scope, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch}
	raw, _ := json.Marshal(in)
	if err := generated.ValidateContractJSON(generated.SchemaIDQualificationInspectRequest, raw, generated.ContractExact); err != nil {
		t.Fatal("inspection fixture schema", err)
	}
	var before int
	if err = f.s.conn.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM host_discovery_attempts`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	// This existing fixture has an inert synthetic target row, but deliberately
	// lacks a real acknowledged activation receipt. It cannot authorize a dial.
	if _, _, err = NewHostDiscoveryRepository(f.s).ResolveQualificationTarget(f.ctx, in); Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("unapplied target accepted or query invalid: %v", err)
	}
	var after int
	if err = f.s.conn.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM host_discovery_attempts`).Scan(&after); err != nil || before != after {
		t.Fatalf("inspection created attempt %d -> %d: %v", before, after, err)
	}
	now, err := NewPlanRepository(f.s).CurrentRevision(f.ctx)
	if err != nil || now != current {
		t.Fatal("read-only inspection changed revision")
	}
}
