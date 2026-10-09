package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"slices"
	"time"
)

func validateBaselineCurrent(row discoveryRow, p generated.Plan, now time.Time) error {
	if p.HostAction == nil || p.HostAccessSequence != nil || p.HostBaselineScope == nil {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	scope, e := debianbaseline.ScopeForRequest(*p.HostAction)
	if e != nil || scope == nil || hostaction.Digest(scope) != hostaction.Digest(p.HostBaselineScope) {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	if _, e = actionTarget(row, *p.HostAction); e != nil {
		return e
	}
	for id, digest := range map[string]string{scope.SubjectHostID: scope.SubjectIdentityDigest, scope.ExecutionHostID: scope.ExecutionIdentityDigest} {
		var actual string
		var epoch int64
		if row(`SELECT identity_digest,recovery_epoch FROM managed_hosts WHERE host_id=?`, id).Scan(&actual, &epoch) != nil || actual != digest || epoch != p.Binding.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
	}
	if p.HostAction.ActionID == "debian.volume-recovery.verify" {
		in, e := debianbaseline.DecodeRecoveryInput([]byte(p.HostAction.ActionInput))
		if e != nil {
			return e
		}
		if e = validateCurrentVolumeDeclaration(row, in.Binding); e != nil {
			return e
		}
		return validatePriorVolumeReceipt(row, in, now)
	}
	if p.HostAction.ActionID == "debian.volume.observe" {
		in, e := debianbaseline.DecodeInput([]byte(p.HostAction.ActionInput))
		if e != nil {
			return e
		}
		for _, v := range in.Volumes {
			if e = validateCurrentVolumeDeclaration(row, v); e != nil {
				return e
			}
		}
	}
	return nil
}
func validatePriorVolumeReceipt(row discoveryRow, in generated.VolumeRecoveryInput, now time.Time) error {
	var raw, resultRaw, receiptRaw []byte
	var status string
	if row(`SELECT c.measurement_bytes,c.result_bytes,e.canonical_bytes,c.status FROM host_control_results c JOIN execution_receipts e ON e.receipt_id=c.receipt_id AND e.result_digest=c.result_digest AND e.status='succeeded' JOIN plan_run_steps s ON s.run_id=c.run_id AND s.step_id=c.step_id AND s.status='succeeded' AND s.effect_state='verified' WHERE c.host_id=? AND c.host_identity_digest=? AND c.recovery_epoch=? AND c.control_id=? ORDER BY c.observed_at DESC,c.rowid DESC LIMIT 1`, in.Binding.HostID, in.Binding.HostIdentityDigest, in.Binding.RecoveryEpoch, "linux.volume-encryption:"+in.Binding.VolumeID).Scan(&raw, &resultRaw, &receiptRaw, &status) != nil || status != "passed" || hostaction.BytesDigest(receiptRaw) != in.PriorVolumeReceiptDigest {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	var m generated.AccessMeasurement
	var result generated.HostActionResult
	var receipt generated.ExecutionReceipt
	if json.Unmarshal(raw, &m) != nil || json.Unmarshal(resultRaw, &result) != nil || json.Unmarshal(receiptRaw, &receipt) != nil || hostaction.ValidateResult(result) != nil || result.ResultDigest != receipt.ResultDigest || m.MeasurementDigest != hostaction.MeasurementDigest(m) || m.Volume == nil || m.Volume.Kind != "mapping" || hostaction.Digest(m.Volume.Binding) != hostaction.Digest(in.Binding) || m.ProfileLockDigest != in.ProfileLockDigest {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	found := false
	for _, v := range result.ControlMeasurements {
		found = found || hostaction.Digest(v) == hostaction.Digest(m)
	}
	at, e := time.Parse(time.RFC3339, m.ObservedAt)
	if !found || e != nil || at.After(now.Add(time.Second)) || now.Sub(at) > 10*time.Minute {
		return actionError(generated.ErrorCodePlanStale)
	}
	return nil
}
func baselineProjection(p generated.Plan) (generated.DebianAccessInput, error) {
	if p.HostAction == nil || p.HostBaselineScope == nil {
		return generated.DebianAccessInput{}, actionError(generated.ErrorCodeIntegrityFailure)
	}
	scope := p.HostBaselineScope
	out := generated.DebianAccessInput{HostID: scope.SubjectHostID, HostIdentityDigest: scope.SubjectIdentityDigest, ProfileID: scope.ProfileID, ProfileLockDigest: scope.ProfileLockDigest, ActionVersion: "1.0.0"}
	if p.HostAction.ActionID == "debian.volume-recovery.verify" {
		in, e := debianbaseline.DecodeRecoveryInput([]byte(p.HostAction.ActionInput))
		out.ProfileLock = in.ProfileLock
		return out, e
	}
	in, e := debianbaseline.DecodeInput([]byte(p.HostAction.ActionInput))
	out.ProfileLock = in.ProfileLock
	return out, e
}
func validateBaselineMeasurement(p generated.Plan, m generated.AccessMeasurement, ordinal int) error {
	scope := p.HostBaselineScope
	if scope == nil || ordinal >= len(scope.ControlIDs) || m.ControlID != scope.ControlIDs[ordinal] || m.ProducerID != "debian-baseline" || m.ProducerVersion != "1.0.0" || p.HostAction == nil || m.Probe != nil || len(m.DestinationOwnership) != 0 {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	volumeAction := p.HostAction.ActionID == "debian.volume.observe" || p.HostAction.ActionID == "debian.volume-recovery.verify"
	if volumeAction != (m.Volume != nil) {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	if m.Volume != nil {
		prefix := "linux.volume-encryption:"
		if p.HostAction.ActionID == "debian.volume-recovery.verify" {
			prefix = "linux.volume-recovery:"
		}
		if m.ControlID != prefix+m.Volume.Binding.VolumeID {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if m.ConfigurationDigest != hostaction.Digest(m.Volume.Binding) {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if m.Kind != "volume" || m.Baseline != nil || m.Volume.Binding.HostID != scope.SubjectHostID || m.Volume.Binding.HostIdentityDigest != scope.SubjectIdentityDigest || m.Volume.Binding.RecoveryEpoch != p.Binding.RecoveryEpoch || m.Volume.ObservedAt != m.ObservedAt {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if p.HostAction.ActionID == "debian.volume-recovery.verify" {
			in, e := debianbaseline.DecodeRecoveryInput([]byte(p.HostAction.ActionInput))
			if e != nil || m.Volume.Kind != "recovery" || m.Volume.PriorVolumeReceiptDigest != in.PriorVolumeReceiptDigest || hostaction.Digest(m.Volume.Binding) != hostaction.Digest(in.Binding) {
				return actionError(generated.ErrorCodeIntegrityFailure)
			}
		} else {
			in, e := debianbaseline.DecodeInput([]byte(p.HostAction.ActionInput))
			if e != nil || p.HostAction.ActionID != "debian.volume.observe" || m.Volume.Kind != "mapping" || m.Volume.PriorVolumeReceiptDigest != "" || !slices.ContainsFunc(in.Volumes, func(v generated.HostVolumeBinding) bool {
				return hostaction.Digest(v) == hostaction.Digest(m.Volume.Binding)
			}) {
				return actionError(generated.ErrorCodeIntegrityFailure)
			}
		}
	} else if m.ConfigurationDigest != p.HostAction.ActionInputDigest || m.Kind != "baseline" || m.Baseline == nil || m.Baseline.NativeQualificationDigest != "" || m.Baseline.AIDEReferenceDigest != "" && m.ControlID != "linux.aide-integrity" || m.Status == "passed" && m.Baseline.Verification == "unavailable" {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	return nil
}
func (r *HostActionRepository) ValidateBaselinePreparation(ctx context.Context, request generated.HostActionRequest) error {
	scope, e := debianbaseline.ScopeForRequest(request)
	if e != nil {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	if scope == nil {
		return nil
	}
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if e := validateBaselineCurrent(row, generated.Plan{HostAction: &request, HostBaselineScope: scope, Binding: generated.PlanBinding{RecoveryEpoch: request.RecoveryEpoch}}, r.store.config.Clock()); e != nil {
			return e
		}
		for _, id := range []string{scope.SubjectHostID, scope.ExecutionHostID} {
			if _, e := adoptionGrant(ctx, row, id, "host", "author", "host.action.prepare", true); e != nil {
				return e
			}
		}
		return nil
	})
}

// Desired declarations are inert, revisioned API-authored state. The subsequent
// exact action plan supplies human execution approval; the declaration is not
// an applied volume proof. Newer desired revisions immediately invalidate it.
func validateCurrentVolumeDeclaration(row discoveryRow, b generated.HostVolumeBinding) error {
	var raw []byte
	var reason string
	if row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? ORDER BY declaration_revision DESC LIMIT 1`, b.DeclarationID).Scan(&raw, &reason) != nil {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	var d generated.DeclarationRevision
	if !decodeStoredDeclaration(raw, reason, &d) || d.DeclarationType != "host.volume" || d.DeclarationID != b.DeclarationID || d.Revision != b.DeclarationRevision || d.RecoveryEpoch != b.RecoveryEpoch || d.Status == "superseded" {
		return actionError(generated.ErrorCodePlanStale)
	}
	count := 0
	for _, x := range d.Extensions {
		if x.Name == "x-host-volume-binding" {
			if x.ValueDigest != hostaction.Digest(b) {
				return actionError(generated.ErrorCodePlanStale)
			}
			count++
		}
	}
	if count != 1 {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	return nil
}
