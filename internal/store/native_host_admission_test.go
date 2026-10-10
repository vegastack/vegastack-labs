package store

import (
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"testing"
)

func TestNativeHostCollectionHasClosedStageGateBinding(t *testing.T) {
	for _, in := range []generated.NativeCollectRequest{{Stage: "baseline", ProfileID: "profile"}, {Stage: "baseline", HostID: "host", HostGateID: "platform-safety"}, {Stage: "baseline", HostID: "host", HostGateID: "host.hardening-baseline"}, {Stage: "role", HostID: "host", HostGateID: "host.role-admission"}} {
		if _, _, ok := NativeCollectSubject(in); !ok {
			t.Fatal("finite subject rejected", in)
		}
	}
	for _, in := range []generated.NativeCollectRequest{{Stage: "role", HostID: "host", HostGateID: "platform-safety"}, {Stage: "baseline", HostID: "host", HostGateID: "host.role-admission"}, {Stage: "baseline", HostID: "host"}, {Stage: "baseline", HostGateID: "platform-safety"}, {Stage: "recovery", HostID: "host", HostGateID: "host.role-admission"}} {
		if _, _, ok := NativeCollectSubject(in); ok {
			t.Fatal("stage/subject substitution accepted", in)
		}
	}
}

func TestNativeHostIdentityJoinsAppliedAdoptionAndCurrentReadScope(t *testing.T) {
	f := newRegistrationStoreFixture(t)
	f.request.Confirmation.IdentityClass = "qualified-virtual"
	d := f.Stage(t)
	if _, err := f.repo.Apply(f.ctx, f.bind(t, d)); err != nil {
		t.Fatal(err)
	}
	var targetKey string
	err := f.s.Read(f.ctx, func(tx ReadTx) error {
		target, e := discoveryTarget(func(q string, a ...any) *sql.Row { return tx.queryRow(f.ctx, q, a...) }, "candidate-a")
		if e == nil {
			targetKey = target.Binding.HostKey
		}
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := hostreplacement.SSHHostKeyDigest(targetKey)
	if err != nil {
		t.Fatal(err)
	}
	g := generated.QualificationGuest{HostID: f.request.HostID, HostIdentityDigest: f.request.Confirmation.IdentityDigest, InstanceID: "synthetic-serial", MachineID: "synthetic-machine", SSHHostKeyDigest: key}
	r := NewGateRepository(f.s)
	s, digest, err := r.ResolveNativeHostAdmission(f.ctx, g.HostID, g)
	if err != nil || digest == "" || s.Host.Status != "adopted-unadmitted" || len(s.Qualifications) != 0 {
		t.Fatal("identity join changed admission or lost actual observation", err)
	}
	for _, name := range []string{"serial", "machine", "key", "foreign-host"} {
		wrong := g
		switch name {
		case "serial":
			wrong.InstanceID = "foreign"
		case "machine":
			wrong.MachineID = "foreign"
		case "key":
			wrong.SSHHostKeyDigest = hostaction.Digest("foreign")
		case "foreign-host":
			wrong.HostID = "foreign"
		}
		if _, _, err := r.ResolveNativeHostAdmission(f.ctx, wrong.HostID, wrong); err == nil {
			t.Fatal("foreign independent identity admitted", name)
		}
	}
	// A later normal credential target revision must retain the original
	// independently observed identity confirmation, rather than re-author it.
	var current generated.HostDiscoveryTarget
	if err := f.s.Read(f.ctx, func(tx ReadTx) error {
		target, e := discoveryTarget(func(q string, a ...any) *sql.Row { return tx.queryRow(f.ctx, q, a...) }, "candidate-a")
		current = target.Binding
		return e
	}); err != nil {
		t.Fatal(err)
	}
	current.Revision = 2
	current.MaterialVersion = "rotated"
	draft := generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: current, ExpectedTargetRevision: 1, Action: "activate", IdempotencyKey: "rotated-target"}
	raw, _ := json.Marshal(draft)
	if _, err := f.s.conn.ExecContext(f.ctx, `INSERT INTO host_discovery_drafts VALUES('rotated-target','candidate-a',2,1,'activate',?,?,'operator-a',1,0)`, hostdiscovery.Digest(draft), raw); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.conn.ExecContext(f.ctx, `INSERT INTO host_discovery_targets VALUES('candidate-a',2,'rotated-target','active','fixture-plan',0)`); err != nil {
		t.Fatal(err)
	}
	if _, actual, err := r.ResolveNativeHostAdmission(f.ctx, g.HostID, g); err != nil || actual != digest {
		t.Fatal("credential revision rewrote historical identity", err)
	}
	if _, err := f.s.conn.ExecContext(f.ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE capability='host.read'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.ResolveNativeHostAdmission(f.ctx, g.HostID, g); err == nil {
		t.Fatal("revoked host read accepted")
	}
}

func TestNativeHostControlBindingChangesWithRealMeasurementLineage(t *testing.T) {
	s := HostAdmissionSnapshot{BindingDigest: hostaction.Digest("host"), Measurements: []HostAdmissionMeasurement{{Receipt: generated.ExecutionReceipt{LeaseID: "owning-lease"}}}}
	original := NativeHostControlsDigest(s)
	s.Evidence = []generated.GateEvidence{{EvidenceID: "new-applied-gate"}}
	if NativeHostControlsDigest(s) != original {
		t.Fatal("ordinary gate application invalidated measurements")
	}
	s.Measurements[0].Receipt.LeaseID = "foreign"
	if NativeHostControlsDigest(s) == original {
		t.Fatal("foreign actual receipt did not change binding")
	}
}
