package store

import (
	"context"
	"database/sql"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// LookupNativeProducerReference exposes only the real terminal tuple for a
// scoped reader. A reference grants no execution or evidence authority; native
// collection repeats the complete producer join and fresh observer checks.
func (r *GateRepository) LookupNativeProducerReference(ctx context.Context, in generated.NativeProducerLookupRequest, scope generated.QualificationScope) (out generated.NativeProducerReference, err error) {
	out, _, err = r.LookupNativeProducerReferenceAndBundleDigest(ctx, in, scope)
	return
}

// The digest comes from the same completed producer snapshot as the lease,
// never from caller input or a second unrelated execution lookup.
func (r *GateRepository) LookupNativeProducerReferenceAndBundleDigest(ctx context.Context, in generated.NativeProducerLookupRequest, scope generated.QualificationScope) (out generated.NativeProducerReference, bundleDigest string, err error) {
	out, bundleDigest, _, err = r.LookupNativeProducerDataBindings(ctx, in, scope)
	return
}

// The receipt digest is resolved with the reference from the same authoritative
// snapshot. It exports no receipt bytes or evidence/execution authority.
func (r *GateRepository) LookupNativeProducerDataBindings(ctx context.Context, in generated.NativeProducerLookupRequest, scope generated.QualificationScope) (out generated.NativeProducerReference, bundleDigest, receiptDigest string, err error) {
	if r == nil || r.store == nil || !nativeContract(generated.SchemaIDNativeProducerLookupRequest, in) {
		return out, "", "", actionError(generated.ErrorCodeInputInvalid)
	}
	stage := ""
	for _, candidate := range []string{"baseline", "role", "recovery"} {
		for _, scenario := range generated.NativeQualificationScenarios(candidate) {
			if scenario == in.ScenarioID {
				stage = candidate
			}
		}
	}
	if stage == "" {
		return out, "", "", actionError(generated.ErrorCodeInputInvalid)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		q := nativeQuery{tx, func(query string, args ...any) *sql.Row { return tx.queryRow(ctx, query, args...) }, func(query string, args ...any) (*sql.Rows, error) { return tx.query(ctx, query, args...) }}
		for _, g := range []struct{ id, kind, cap string }{{in.RunID, "run", "run.read"}, {in.HostID, "host", "host.read"}} {
			if _, e := adoptionGrant(ctx, q.row, g.id, g.kind, "read", g.cap, false); e != nil {
				return e
			}
		}
		rows, e := q.rows(`SELECT x.lease_id FROM execution_receipts x JOIN target_execution_leases l ON l.lease_id=x.lease_id AND l.run_id=x.run_id AND l.step_id=x.step_id JOIN plan_runs r ON r.run_id=x.run_id WHERE x.run_id=? AND x.step_id=? AND r.plan_id=? AND r.plan_digest=? AND r.recovery_epoch=? AND l.recovery_epoch=r.recovery_epoch AND x.status IN ('succeeded','failed','partial') AND l.status='released' LIMIT 2`, in.RunID, in.StepID, in.PlanID, in.PlanDigest, in.RecoveryEpoch)
		if e != nil {
			return nativeError()
		}
		var lease string
		if !rows.Next() {
			rows.Close()
			return nativeError()
		}
		e = rows.Scan(&lease)
		extra := rows.Next()
		rowErr := rows.Err()
		rows.Close()
		if e != nil || rowErr != nil || extra || lease == "" {
			return nativeError()
		}
		ref := generated.NativeProducerReference{Schema: generated.SchemaIDNativeProducerReference, SchemaVersion: "1.0.0", ScenarioID: in.ScenarioID, HostID: in.HostID, PlanID: in.PlanID, PlanDigest: in.PlanDigest, RunID: in.RunID, StepID: in.StepID, LeaseID: lease}
		snapshot, e := r.resolveNativeProducers(ctx, q, generated.NativeCollectRequest{ScopeDigest: in.ScopeDigest, Stage: stage, RecoveryEpoch: in.RecoveryEpoch, Producers: []generated.NativeProducerReference{ref}}, false)
		if e != nil {
			return e
		}
		if len(snapshot.Producers) != 1 || len(snapshot.Executions) != 1 || !nativeLookupScopeMatches(scope, in, snapshot, r.store.config.Clock().UTC()) {
			return nativeError()
		}
		out = snapshot.Producers[0].Reference
		receiptDigest = snapshot.Producers[0].ReceiptDigest
		if in.ScenarioID == "action-replay" || in.ScenarioID == "action-concurrency" {
			execution := snapshot.Executions[0]
			if execution.Result == nil || execution.Receipt.Status != "succeeded" || execution.Result.Status != "succeeded" || !execution.Result.EffectObserved || execution.Result.BundleDigest == "" {
				return nativeError()
			}
			bundleDigest = execution.Result.BundleDigest
		}
		return nil
	})
	if err != nil {
		out = generated.NativeProducerReference{}
		bundleDigest = ""
		receiptDigest = ""
	}
	return
}

// NativeScopeAuthority accepts a changed controller only through the existing
// verified restore bridge resolved in the same database snapshot.
func NativeScopeAuthority(scope generated.QualificationScope, s NativeProducerSnapshot) bool {
	if scope.ControllerInstanceID == "" || s.ControllerInstanceID == "" {
		return false
	}
	if scope.ControllerInstanceID == s.ControllerInstanceID {
		return true
	}
	b := s.VerifiedRestoreBinding
	if b == nil || b.PriorInstanceID != scope.ControllerInstanceID || b.NewInstanceID != s.ControllerInstanceID || b.NextRecoveryEpoch != s.Revision.RecoveryEpoch || b.NextRecoveryEpoch != b.PriorRecoveryEpoch+1 {
		return false
	}
	former, replacement := false, false
	for _, g := range scope.Guests {
		former = former || g.HostID == b.FormerHostID
		replacement = replacement || g.HostID == b.ReplacementHostID
	}
	return former && replacement
}
func nativeLookupScopeMatches(scope generated.QualificationScope, in generated.NativeProducerLookupRequest, s NativeProducerSnapshot, now time.Time) bool {
	issued, e1 := time.Parse(time.RFC3339, scope.IssuedAt)
	expires, e2 := time.Parse(time.RFC3339, scope.ExpiresAt)
	if e1 != nil || e2 != nil || now.Before(issued) || !now.Before(expires) || !expires.After(issued) || expires.Sub(issued) > 4*time.Hour || hostaction.Digest(scope) != in.ScopeDigest || !NativeScopeAuthority(scope, s) || len(s.Producers) != 1 {
		return false
	}
	matches := 0
	for _, g := range scope.Guests {
		if g.HostID == in.HostID && g.HostIdentityDigest != "" && g.HostIdentityDigest == s.Producers[0].HostIdentityDigest {
			matches++
		}
	}
	return matches == 1
}
