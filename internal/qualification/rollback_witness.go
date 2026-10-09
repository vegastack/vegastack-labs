package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"reflect"
	"time"
)

func ValidateRollbackWitness(scenario string, before, after debianaccess.NativeRollbackObservation) error {
	if scenario != "access-rollback-timeout" && scenario != "access-rollback-reboot" {
		return ErrUnavailable
	}
	if before.RecordDigest == "" || before.RunID == "" || before.FileCount < 1 || before.FirewallCount < 1 || before.State != "armed" || after.State != "restored" || before.CurrentOwnedDigest != before.AppliedOwnedDigest || after.CurrentOwnedDigest != before.BeforeOwnedDigest || before.AppliedOwnedDigest == before.BeforeOwnedDigest || before.ArmedBootID != before.CurrentBootID {
		return ErrUnavailable
	}
	a, b := before, after
	a.State = ""
	b.State = ""
	a.ObservedAt = ""
	b.ObservedAt = ""
	a.ReconciledBootID = ""
	b.ReconciledBootID = ""
	a.CurrentBootID = ""
	b.CurrentBootID = ""
	a.CurrentOwnedDigest = ""
	b.CurrentOwnedDigest = ""
	if !reflect.DeepEqual(a, b) {
		return ErrUnavailable
	}
	armed, e := time.Parse(time.RFC3339Nano, before.ArmedAt)
	deadline, f := time.Parse(time.RFC3339Nano, before.Deadline)
	first, g := time.Parse(time.RFC3339Nano, before.ObservedAt)
	last, h := time.Parse(time.RFC3339Nano, after.ObservedAt)
	if e != nil || f != nil || g != nil || h != nil || deadline.Sub(armed) != 600*time.Second || first.Before(armed) || !first.Before(deadline) || !last.After(first) {
		return ErrUnavailable
	}
	if scenario == "access-rollback-timeout" {
		if last.Before(deadline) || after.CurrentBootID != before.CurrentBootID {
			return ErrUnavailable
		}
	} else if after.CurrentBootID == before.CurrentBootID || after.ReconciledBootID != after.CurrentBootID {
		return ErrUnavailable
	}
	return nil
}
