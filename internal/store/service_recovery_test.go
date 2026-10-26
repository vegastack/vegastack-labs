package store

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicerecovery"
	"testing"
	"time"
)

func TestServiceRecoveryCannotPromoteIncompleteOutcome(t *testing.T) {
	q := generated.ServiceRecoveryRequest{Schema: generated.SchemaIDServiceRecoveryRequest, SchemaVersion: "1.0.0", Definition: servicePolicyFixture().Definition, Binding: generated.ServiceRecoveryBinding{Schema: generated.SchemaIDServiceRecoveryBinding, SchemaVersion: "1.0.0", PolicyID: "policy-a", ServiceID: "service-a", ConfigurationDigest: serviceTestDigest, DataClass: "workload", ConsistencyProcedureID: servicerecovery.ConsistencyProcedureID, SourceHostID: "synthetic-host", TargetHostID: "target-host"}, Action: "backup", IdempotencyKey: "request-a", ReasonDigest: serviceTestDigest}
	apply := ServiceRecoveryApply{PlanID: "plan-a", RunID: "run-a"}
	good := servicerecovery.Outcome{Status: "succeeded", BackupPointID: "point-a", SnapshotID: "snapshot-a", ManifestDigest: serviceTestDigest, ContentDigest: serviceTestDigest, RuntimeDigest: serviceTestDigest, SourceImageDigests: []string{serviceTestDigest}, SourceResumed: true, NextAction: "none"}
	for _, fault := range []string{"no-content", "not-resumed", "no-images", "unproved-restore", "unfenced-cutover"} {
		t.Run(fault, func(t *testing.T) {
			out := good
			in := q
			switch fault {
			case "no-content":
				out.ContentDigest = ""
			case "not-resumed":
				out.SourceResumed = false
			case "no-images":
				out.SourceImageDigests = nil
			case "unproved-restore":
				in.Action = "isolated-restore"
				in.BackupPointID = "point-a"
			case "unfenced-cutover":
				in.Action = "migration-cutover"
				in.BackupPointID = "point-a"
				out.IsolatedRestoreVerified = true
				out.TargetWritersEnabled = true
			}
			record, e := serviceRecoveryRecord(in, apply, out, time.Now())
			if e != nil || record.Status != "partial" {
				t.Fatalf("unsupported outcome promoted: %+v %v", record, e)
			}
		})
	}
	record, e := serviceRecoveryRecord(q, apply, good, time.Now())
	if e != nil || record.Status != "succeeded" {
		t.Fatalf("complete actual branch rejected: %+v %v", record, e)
	}
}
