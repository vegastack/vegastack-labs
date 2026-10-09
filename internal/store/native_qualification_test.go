package store

import (
	"database/sql"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func TestNativePublicResolverDoesNotExposeHistoricalProducerWithoutReadGrant(t *testing.T) {
	f := newRegistrationStoreFixture(t)
	for _, g := range []struct{ id, operation, kind, target string }{{"native-author", "gate.evidence.author", "gate", "native.baseline"}, {"native-declaration", "declaration.author", "declaration", "gate-evidence-native-a"}} {
		if _, e := f.s.conn.ExecContext(f.ctx, `INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin','author',?,?,?,NULL,1,'active','now','now')`, g.id, g.operation, g.kind, g.target); e != nil {
			t.Fatal(e)
		}
	}
	d := hostaction.Digest("native")
	in := generated.NativeCollectRequest{Schema: generated.SchemaIDNativeCollectRequest, SchemaVersion: "1.0.0", ScopeDigest: d, Stage: "baseline", EvidenceID: "native-a", ProfileID: "debian-13-amd64", ExpectedStateRevision: 1, IdempotencyKey: "native-a", Producers: []generated.NativeProducerReference{{Schema: generated.SchemaIDNativeProducerReference, SchemaVersion: "1.0.0", ScenarioID: "baseline-access", HostID: "historical-private-host", PlanID: "private-plan", PlanDigest: d, RunID: "private-run", StepID: "private-step", LeaseID: "private-lease"}}}
	got, e := NewGateRepository(f.s).ResolveNativeProducers(f.ctx, in)
	if Code(e) != generated.ErrorCodeAuthorizationDenied || len(got.Producers) != 0 || len(got.Executions) != 0 || len(got.Measurements) != 0 {
		t.Fatalf("private producer leaked or wrong gate: %+v %v", got, e)
	}
}

func TestNativeExecutionProfileRejectsDifferentImmutableProfile(t *testing.T) {
	d := hostaction.Digest("lock")
	e := NativeProducerExecution{Plan: generated.Plan{HostBaselineScope: &generated.HostBaselineScope{ProfileID: "debian-a", ProfileLockDigest: d}}}
	if !NativeExecutionProfileMatches(e, "debian-a", d) || NativeExecutionProfileMatches(e, "debian-b", d) || NativeExecutionProfileMatches(e, "debian-a", hostaction.Digest("other")) {
		t.Fatal("profile substitution accepted")
	}
	if NativeExecutionProfileMatches(NativeProducerExecution{}, "debian-a", d) {
		t.Fatal("absent configuration accepted")
	}
}

func TestNativeLaterStagesCannotBypassInstalledProvenance(t *testing.T) {
	f := newRegistrationStoreFixture(t)
	r := NewGateRepository(f.s)
	for _, stage := range []string{"baseline", "role", "recovery", "future"} {
		t.Run(stage, func(t *testing.T) {
			var got []generated.NativeQualificationPrerequisite
			err := f.s.Read(f.ctx, func(tx ReadTx) error {
				q := nativeQuery{tx, func(query string, a ...any) *sql.Row { return tx.queryRow(f.ctx, query, a...) }, func(query string, a ...any) (*sql.Rows, error) { return tx.query(f.ctx, query, a...) }}
				var err error
				got, err = r.nativePrerequisites(f.ctx, q, generated.NativeQualification{Stage: stage})
				return err
			})
			if stage == "baseline" {
				if err != nil || len(got) != 0 {
					t.Fatal("baseline gained a future-stage dependency")
				}
			} else if Code(err) != generated.ErrorCodePrerequisiteBlocked || len(got) != 0 {
				t.Fatalf("stage %s bypassed trusted prerequisites: %v", stage, err)
			}
		})
	}
}
