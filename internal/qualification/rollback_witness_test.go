package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
	"time"
)

func TestRollbackWitnessRequiresRealWindowPreimageAndBoot(t *testing.T) {
	start := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	d := hostaction.Digest
	before := debianaccess.NativeRollbackObservation{RecordDigest: d("record"), RunID: "run", HostID: "host", HostIdentityDigest: d("host"), PlanID: "plan", InputDigest: d("input"), AuthorizationDigest: d("auth"), BundleDigest: d("bundle"), State: "armed", ArmedAt: start.Format(time.RFC3339), Deadline: start.Add(600 * time.Second).Format(time.RFC3339), ObservedAt: start.Add(time.Second).Format(time.RFC3339), ArmedBootID: "before-boot", CurrentBootID: "before-boot", BeforeOwnedDigest: d("before"), AppliedOwnedDigest: d("applied"), CurrentOwnedDigest: d("applied"), FileCount: 2, FirewallCount: 4}
	after := before
	after.State = "restored"
	after.CurrentOwnedDigest = before.BeforeOwnedDigest
	after.ObservedAt = start.Add(601 * time.Second).Format(time.RFC3339)
	if ValidateRollbackWitness("access-rollback-timeout", before, after) != nil {
		t.Fatal("valid bounded software fixture rejected")
	}
	for name, change := range map[string]func(*debianaccess.NativeRollbackObservation){"short-window": func(o *debianaccess.NativeRollbackObservation) {
		o.ObservedAt = start.Add(599 * time.Second).Format(time.RFC3339)
	}, "wrong-preimage": func(o *debianaccess.NativeRollbackObservation) { o.CurrentOwnedDigest = d("other") }, "different-record": func(o *debianaccess.NativeRollbackObservation) { o.RecordDigest = d("different") }, "uncertain": func(o *debianaccess.NativeRollbackObservation) { o.State = "uncertain" }} {
		t.Run(name, func(t *testing.T) {
			a := after
			change(&a)
			if ValidateRollbackWitness("access-rollback-timeout", before, a) == nil {
				t.Fatal("invalid witness admitted")
			}
		})
	}
	if ValidateRollbackWitness("access-rollback-reboot", before, after) == nil {
		t.Fatal("unchanged boot accepted")
	}
	after.CurrentBootID = "after-boot"
	after.ReconciledBootID = "after-boot"
	after.ObservedAt = start.Add(60 * time.Second).Format(time.RFC3339)
	if ValidateRollbackWitness("access-rollback-reboot", before, after) != nil {
		t.Fatal("changed reconciled boot rejected")
	}
	after.ReconciledBootID = "different-boot"
	if ValidateRollbackWitness("access-rollback-reboot", before, after) == nil {
		t.Fatal("unreconciled boot accepted")
	}
}
