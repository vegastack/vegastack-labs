package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"time"
)

type HostReplacementCredentialBoundary struct{ ReferenceID, ConsumerID, PurposeID, TargetID, ResolverID, MaterialVersion, Status string }
type HostReplacementOutstanding struct{ RunID, StepID, OperationType, EffectState, Status, LeaseID, MaximumExpiresAt string }
type HostReplacementFenceScope struct {
	State                generated.HostReplacementState
	Request              generated.HostReplacementRequest
	ControllerInstanceID string
	RecoveryEpoch        int64
	AuthorityDigest      string
	Credentials          []HostReplacementCredentialBoundary
	Outstanding          []HostReplacementOutstanding
}

// This mirrors only the finite binding fields, not the recovery proof evaluator.
type HostReplacementFenceBinding struct {
	ReplacementID, ControllerInstanceID, OldHostID, NewHostID                  string
	OldIdentityDigest, NewIdentityDigest, FrozenAliasesDigest, AuthorityDigest string
	PlanID, PlanDigest, RunID, StepID, LeaseID                                 string
	RequirementsDigest, QualificationDigest, Nonce, ReceiptID                  string
	RecoveryEpoch, PriorGeneration, NextGeneration                             int64
	IssuedAt, Deadline                                                         time.Time
}
type HostReplacementFenceReceipt struct {
	Binding     HostReplacementFenceBinding
	ChallengeID string
	Transcripts json.RawMessage
	ExpiresAt   time.Time
	Digest      string
}

func (r *HostReplacementRepository) CurrentHostReplacementFenceScope(ctx context.Context, x HostReplacementExecution) (out HostReplacementFenceScope, err error) {
	err = r.store.Read(ctx, func(tx ReadTx) error { return r.replacementFenceScope(ctx, tx, x, &out) })
	return
}
func (r *HostReplacementRepository) replacementFenceScope(ctx context.Context, tx ReadTx, x HostReplacementExecution, out *HostReplacementFenceScope) error {
	row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
	d, e := readReplacementDraft(row, x.DraftID)
	if e != nil {
		return e
	}
	op := hostreplacement.FreezeOperation
	if d.Request.Operation == "commit" {
		op = hostreplacement.CommitOperation
	}
	if _, e = r.execution(ctx, row, x, op); e != nil {
		return e
	}
	event, digest, e := readReplacementEvent(row, x.ReplacementID)
	if e != nil {
		return e
	}
	out.State = event.State
	out.Request = d.Request
	if out.State.Status == "committed" || out.State.BindingDigest != d.BindingDigest {
		return replacementError(generated.ErrorCodeStateConflict)
	}
	if out.State.FreezeEventDigest == "" {
		if event.Type == "frozen" {
			out.State.FreezeEventDigest = digest
		} else if e = row(`SELECT event_digest FROM host_replacement_events WHERE replacement_id=? AND event_type='frozen'`, x.ReplacementID).Scan(&out.State.FreezeEventDigest); e != nil {
			return e
		}
	}
	if e = row(`SELECT instance_id,recovery_epoch FROM system_meta WHERE id=1`).Scan(&out.ControllerInstanceID, &out.RecoveryEpoch); e != nil {
		return e
	}
	host, e := readManagedHost(row, d.Request.OldHostID)
	if e != nil {
		return e
	}
	target, e := discoveryTarget(row, host.TargetID)
	if e != nil {
		return e
	}
	rows, e := tx.query(ctx, `SELECT reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,status FROM credential_reference_versions WHERE target_id IN (?,?) ORDER BY reference_id,material_version`, d.Request.OldHostID, host.TargetID)
	if e != nil {
		return e
	}
	for rows.Next() {
		var b HostReplacementCredentialBoundary
		if e = rows.Scan(&b.ReferenceID, &b.ConsumerID, &b.PurposeID, &b.TargetID, &b.ResolverID, &b.MaterialVersion, &b.Status); e != nil {
			rows.Close()
			return e
		}
		out.Credentials = append(out.Credentials, b)
		if len(out.Credentials) > 64 {
			rows.Close()
			return replacementError(generated.ErrorCodePrerequisiteBlocked)
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, b := range out.Credentials {
		var n int
		if e = row(`SELECT COUNT(*) FROM credential_reference_versions WHERE target_id NOT IN (?,?) AND (reference_id=? AND material_version=? OR fingerprint IN (SELECT fingerprint FROM credential_reference_versions WHERE reference_id=? AND material_version=?))`, d.Request.OldHostID, host.TargetID, b.ReferenceID, b.MaterialVersion, b.ReferenceID, b.MaterialVersion).Scan(&n); e != nil {
			return e
		}
		if n > 0 {
			return replacementError(generated.ErrorCodePrerequisiteBlocked)
		}
	}
	foundDiscovery := false
	for _, b := range out.Credentials {
		if b.ReferenceID == target.Binding.CredentialReferenceID && b.MaterialVersion == target.Binding.MaterialVersion && b.TargetID == host.TargetID && b.ConsumerID == hostdiscovery.Consumer && b.PurposeID == hostdiscovery.Purpose {
			foundDiscovery = true
		}
	}
	if !foundDiscovery {
		return replacementError(generated.ErrorCodePrerequisiteBlocked)
	}
	rows, e = tx.query(ctx, `SELECT s.run_id,s.step_id,s.operation_type,s.effect_state,s.status,COALESCE(s.active_lease_id,''),COALESCE(l.maximum_expires_at,'') FROM plan_run_steps s LEFT JOIN target_execution_leases l ON l.lease_id=s.active_lease_id WHERE s.target_id=? AND (s.status IN ('queued','running') OR s.effect_state IN ('intent-recorded','receipt-recorded','effect-unknown') OR s.status='partial' OR EXISTS (SELECT 1 FROM plan_runs ar JOIN immutable_plans ap ON ap.plan_id=ar.plan_id WHERE ar.run_id=s.run_id AND s.operation_id=json_extract(ap.canonical_bytes,'$.hostAccessSequence.applyOperationId') AND s.effect_state='verified' AND NOT EXISTS (SELECT 1 FROM plan_run_steps cf WHERE cf.run_id=s.run_id AND cf.operation_id=json_extract(ap.canonical_bytes,'$.hostAccessSequence.confirmOperationId') AND cf.status='succeeded' AND cf.effect_state='verified'))) ORDER BY s.run_id,s.step_id`, d.Request.OldHostID)
	if e != nil {
		return e
	}
	for rows.Next() {
		var b HostReplacementOutstanding
		if e = rows.Scan(&b.RunID, &b.StepID, &b.OperationType, &b.EffectState, &b.Status, &b.LeaseID, &b.MaximumExpiresAt); e != nil {
			rows.Close()
			return e
		}
		out.Outstanding = append(out.Outstanding, b)
		if len(out.Outstanding) > 256 {
			rows.Close()
			return replacementError(generated.ErrorCodePrerequisiteBlocked)
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	out.AuthorityDigest = hostaction.Digest(struct {
		Credentials []HostReplacementCredentialBoundary
		Outstanding []HostReplacementOutstanding
	}{out.Credentials, out.Outstanding})
	return nil
}
func validateFenceBinding(b HostReplacementFenceBinding, x HostReplacementExecution, s HostReplacementFenceScope, at time.Time) error {
	if b.ReplacementID != x.ReplacementID || b.ControllerInstanceID != s.ControllerInstanceID || b.RecoveryEpoch != s.RecoveryEpoch || b.OldHostID != s.State.OldHostID || b.NewHostID != s.State.NewHostID || b.OldIdentityDigest != s.State.OldIdentityDigest || b.NewIdentityDigest != s.State.NewIdentityDigest || b.AuthorityDigest != s.AuthorityDigest || b.FrozenAliasesDigest != hostaction.Digest(s.State.AliasBindings) || b.PriorGeneration != s.State.PriorOwnershipGeneration || b.NextGeneration != s.State.ProposedOwnershipGeneration || b.PlanID != x.PlanID || b.PlanDigest != x.PlanDigest || b.RunID != x.RunID || b.StepID != x.StepID || b.LeaseID != x.LeaseID || len(b.RequirementsDigest) != 71 || len(b.QualificationDigest) != 71 || b.Nonce == "" || b.ReceiptID == "" || b.IssuedAt.After(at) || at.Sub(b.IssuedAt) > 60*time.Second || !at.Before(b.Deadline) || b.Deadline.Sub(b.IssuedAt) > 60*time.Second || len(s.Credentials) == 0 || len(s.Outstanding) != 0 {
		return replacementError(generated.ErrorCodePrerequisiteBlocked)
	}
	return nil
}
func (r *HostReplacementRepository) PersistFenceChallenge(ctx context.Context, x HostReplacementExecution, raw []byte, expectedDigest ...string) error {
	var b HostReplacementFenceBinding
	if len(raw) > 16384 || json.Unmarshal(raw, &b) != nil {
		return replacementError(generated.ErrorCodeInputInvalid)
	}
	digest := hostaction.Digest(b)
	if len(expectedDigest) > 0 && expectedDigest[0] != digest {
		return replacementError(generated.ErrorCodeIntegrityFailure)
	}
	intent := discoveryIntent(x.Attribution, "host.replacement.fence-challenged", x.ReplacementID, hostaction.Digest([]string{x.RunID, x.StepID, b.Nonce}), digest)
	_, err := r.store.executeAuditIntent(ctx, intent, false, func(ctx context.Context, tx *sql.Tx) error {
		var scope HostReplacementFenceScope
		if e := r.replacementFenceScope(ctx, ReadTx{handle: tx}, x, &scope); e != nil {
			return e
		}
		if e := validateFenceBinding(b, x, scope, r.store.config.Clock()); e != nil {
			return e
		}
		row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
		old, _, e := readReplacementEvent(row, x.ReplacementID)
		if e != nil {
			return e
		}
		old.Sequence++
		old.Type = "fence-challenged"
		old.Execution = x
		old.State = scope.State
		old.AuthorityDigest = scope.AuthorityDigest
		old.Challenge = append([]byte(nil), raw...)
		old.FenceReceipt = nil
		old.At = replacementNow(r.store)
		_, e = insertReplacementEvent(ctx, tx, old)
		return e
	})
	return err
}
func (r *HostReplacementRepository) RecordFenceReceipt(ctx context.Context, x HostReplacementExecution, raw []byte) error {
	var receipt HostReplacementFenceReceipt
	if len(raw) > 131072 || json.Unmarshal(raw, &receipt) != nil {
		return replacementError(generated.ErrorCodeInputInvalid)
	}
	digest := receipt.Digest
	receipt.Digest = ""
	if digest != hostaction.Digest(receipt) {
		return replacementError(generated.ErrorCodeIntegrityFailure)
	}
	receipt.Digest = digest
	intent := discoveryIntent(x.Attribution, "host.replacement.fence-observed", x.ReplacementID, hostaction.Digest([]string{x.RunID, x.StepID, receipt.Binding.ReceiptID}), digest)
	_, err := r.store.executeAuditIntent(ctx, intent, false, func(ctx context.Context, tx *sql.Tx) error {
		var scope HostReplacementFenceScope
		if e := r.replacementFenceScope(ctx, ReadTx{handle: tx}, x, &scope); e != nil {
			return e
		}
		if e := validateFenceBinding(receipt.Binding, x, scope, r.store.config.Clock()); e != nil {
			return e
		}
		row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
		event, _, e := readReplacementEvent(row, x.ReplacementID)
		if e != nil {
			return e
		}
		var challenge HostReplacementFenceBinding
		if event.Type != "fence-challenged" || event.AuthorityDigest != scope.AuthorityDigest || json.Unmarshal(event.Challenge, &challenge) != nil || hostaction.Digest(challenge) != hostaction.Digest(receipt.Binding) || receipt.ChallengeID != "host-generation/"+hostaction.Digest(challenge)[7:] || !r.store.config.Clock().Before(receipt.ExpiresAt) || receipt.ExpiresAt.After(challenge.Deadline) || len(receipt.Transcripts) < 3 {
			return replacementError(generated.ErrorCodePlanStale)
		}
		event.Sequence++
		event.Type = "fence-observed"
		event.FenceReceipt = append([]byte(nil), raw...)
		event.At = replacementNow(r.store)
		_, e = insertReplacementEvent(ctx, tx, event)
		return e
	})
	return err
}
