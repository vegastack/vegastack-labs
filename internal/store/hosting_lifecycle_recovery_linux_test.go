//go:build linux

package store

import (
	"encoding/json"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostinglifecycle"
)

func TestHostingLifecycleExplicitPartialRecovery(t *testing.T) {
	for _, known := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy-empty-receipt", true: "created-project-retention-missing"}[known], func(t *testing.T) { testHostingLifecycleExplicitPartialRecovery(t, known) })
	}
}
func testHostingLifecycleExplicitPartialRecovery(t *testing.T, known bool) {
	f, r, in := newHostingLifecycleFixture(t)
	defer f.s.Close()
	owned := []generated.HostingOwnedResource{{Schema: generated.SchemaIDHostingOwnedResource, SchemaVersion: "1.0.0", Kind: "harbor-project", ExternalID: "7", ParentID: "project-a"}}
	var partialOwned []generated.HostingOwnedResource
	if known {
		partialOwned = owned
	}
	apply := seedHostingLifecycleExecution(t, f, in)
	if err := r.Begin(f.ctx, apply); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Complete(f.ctx, apply, hostinglifecycle.Outcome{Status: "partial", OwnedResources: partialOwned}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.conn.ExecContext(f.ctx, `UPDATE plan_runs SET status='partial' WHERE run_id=?`, apply.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.conn.ExecContext(f.ctx, `UPDATE target_execution_leases SET status='released' WHERE lease_id=?`, apply.LeaseID); err != nil {
		t.Fatal(err)
	}
	prior, err := r.Get(f.ctx, in.TargetID)
	if err != nil {
		t.Fatal(err)
	}
	in.ExpectedLifecycleRevision = prior.Revision
	revision, err := NewPlanRepository(f.s).CurrentRevision(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	in.ExpectedStateRevision = revision.StateRevision
	if _, err := r.OwnedResources(f.ctx, in); Code(err) != generated.ErrorCodeRecoveryRequired {
		t.Fatalf("ordinary replay allowed: %v", err)
	}

	raw, _ := json.Marshal(in)
	var request map[string]any
	_ = json.Unmarshal(raw, &request)
	request["recoveryRunId"] = prior.RunID
	request["recoveryRecordDigest"] = hostinglifecycle.Digest(prior)
	request["recoveryResources"] = owned
	raw, _ = json.Marshal(request)
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	got, err := r.OwnedResources(f.ctx, in)
	if err != nil || hostinglifecycle.Digest(got) != hostinglifecycle.Digest(owned) {
		t.Fatalf("explicit partial recovery failed: resources=%v error=%v", got, err)
	}
	after, err := r.Get(f.ctx, in.TargetID)
	if err != nil || hostinglifecycle.Digest(after) != hostinglifecycle.Digest(prior) {
		t.Fatal("recovery preparation rewrote prior record", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*generated.HostingLifecycleRequest)
	}{
		{"wrong-run", func(q *generated.HostingLifecycleRequest) { q.RecoveryRunID = "another-run" }},
		{"wrong-record", func(q *generated.HostingLifecycleRequest) {
			q.RecoveryRecordDigest = hostinglifecycle.Digest("other-record")
		}},
		{"stale-revision", func(q *generated.HostingLifecycleRequest) { q.ExpectedLifecycleRevision++ }},
		{"changed-config", func(q *generated.HostingLifecycleRequest) {
			q.ConfigurationDigest = hostinglifecycle.Digest("other-config")
		}},
		{"missing-proof", func(q *generated.HostingLifecycleRequest) { q.RecoveryRecordDigest = "" }},
		{"duplicate-resource", func(q *generated.HostingLifecycleRequest) {
			q.RecoveryResources = append(q.RecoveryResources, q.RecoveryResources[0])
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := in
			q.RecoveryResources = append([]generated.HostingOwnedResource(nil), in.RecoveryResources...)
			tc.change(&q)
			if _, e := r.OwnedResources(f.ctx, q); e == nil {
				t.Fatal("invalid recovery accepted")
			}
		})
	}
	// A new acknowledged execution appends a verified result; the old partial is
	// retained and the consumed original acknowledgement is never reused.
	in.IdempotencyKey = "hosting-recovery"
	next := seedHostingLifecycleExecution(t, f, in)
	if next.RunID == apply.RunID {
		t.Fatal("reused original run")
	}
	if err := r.Begin(f.ctx, next); err != nil {
		t.Fatal(err)
	}
	proof, err := r.Complete(f.ctx, next, hostinglifecycle.Outcome{Status: "succeeded", ResultDigest: serviceTestDigest, OwnedResources: owned})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(f.ctx, next.PlanID, next.RunID, proof); err != nil {
		t.Fatal(err)
	}
	var oldRaw []byte
	if err := f.s.conn.QueryRowContext(f.ctx, `SELECT canonical_bytes FROM hosting_lifecycle_records WHERE target_id=? AND revision=1`, in.TargetID).Scan(&oldRaw); err != nil {
		t.Fatal(err)
	}
	var retained generated.HostingLifecycleRecord
	if json.Unmarshal(oldRaw, &retained) != nil || hostinglifecycle.Digest(retained) != hostinglifecycle.Digest(prior) {
		t.Fatal("old partial history changed")
	}
}
