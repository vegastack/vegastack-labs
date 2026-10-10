package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

// ResolveNativeProfileQualification reuses the profile-only evidence resolution
// already used by nativePrerequisites. The empty Host is intentional: this read
// qualifies a tested profile and cannot stand in for host/workload admission.
func (r *GateRepository) ResolveNativeProfileQualification(ctx context.Context, profileID, stage string) (out HostAdmissionSnapshot, err error) {
	if r == nil || r.store == nil || !gateScopeID.MatchString(profileID) || !slices.Contains([]string{"baseline", "role", "recovery"}, stage) {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		if e := tx.queryRow(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&out.Revision.StateRevision, &out.Revision.RecoveryEpoch); e != nil {
			return e
		}
		var currentProfile string
		if e := tx.queryRow(ctx, `SELECT profile_id FROM gate_applied_profiles WHERE recovery_epoch=? AND state_revision<=? ORDER BY state_revision DESC,binding_id DESC LIMIT 1`, out.Revision.RecoveryEpoch, out.Revision.StateRevision).Scan(&currentProfile); e != nil {
			if e == sql.ErrNoRows {
				return actionError(generated.ErrorCodeResourceNotFound)
			}
			return e
		}
		if currentProfile != profileID {
			return actionError(generated.ErrorCodeResourceNotFound)
		}
		out.Profile.ProfileID = profileID
		out.ProfileLock.ExecutableVersion = r.store.config.ToolVersion
		out.Bundles = map[string]generated.GateEvidenceBundle{}
		out.AppliedBindings = map[string]HostAppliedBinding{}
		out.NativeProducerBindings = map[string]HostNativeProducerBinding{}
		out.PrerequisiteDigests = map[string]string{}
		out.PrerequisiteEvidenceIDs = map[string]string{}
		var raw []byte
		var bundleDigest, selectedEvidenceID string
		e := tx.queryRow(ctx, `SELECT d.bundle_bytes,e.bundle_digest,e.evidence_id FROM gate_applied_evidence e JOIN gate_evidence_drafts d ON d.draft_id=e.draft_id WHERE e.gate_id=? AND e.subject_id=? AND e.status='applied' AND e.recovery_epoch=? AND e.state_revision<=? AND NOT EXISTS(SELECT 1 FROM gate_applied_evidence later WHERE later.recovery_epoch=e.recovery_epoch AND later.state_revision<=? AND (later.supersedes_evidence_id=e.evidence_id OR later.revokes_evidence_id=e.evidence_id)) ORDER BY e.state_revision DESC,e.evidence_id DESC LIMIT 1`, "native."+stage, profileID, out.Revision.RecoveryEpoch, out.Revision.StateRevision, out.Revision.StateRevision).Scan(&raw, &bundleDigest, &selectedEvidenceID)
		if e == sql.ErrNoRows {
			return nil
		}
		if e != nil {
			return e
		}
		var bundle generated.GateEvidenceBundle
		if len(raw) > 65536 || generated.ValidateContractJSON(generated.SchemaIDGateEvidenceBundle, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &bundle) != nil || hostaction.Digest(bundle) != bundleDigest {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		p := bundle.NativeQualification
		if p == nil || p.ProfileID != profileID || p.Stage != stage || p.RecoveryEpoch != out.Revision.RecoveryEpoch {
			return nil
		}
		out.ProfileLockDigest = p.ProfileLockDigest
		if r.hostProvenance == nil {
			return nil
		}
		gates := []string{"native.baseline"}
		if stage != "baseline" {
			gates = append(gates, "native.role")
		}
		if stage == "recovery" {
			gates = append(gates, "native.recovery")
		}
		if err := r.admissionEvidenceStages(ctx, tx, &out, gates); err != nil {
			return err
		}
		// The generic duty selector may omit a newer malformed/foreign check.
		// It must never turn this profile read into an older-proof fallback.
		for _, qualified := range out.Qualifications {
			if qualified.Stage == stage && qualified.EvidenceID == selectedEvidenceID {
				return nil
			}
		}
		out.Qualifications = nil
		return nil
	})
	if err != nil {
		out = HostAdmissionSnapshot{}
	}
	return
}
