package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"time"

	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func (r *GateRepository) ResolveHostAdmission(ctx context.Context, hostID string) (out HostAdmissionSnapshot, err error) {
	if r == nil || r.store == nil || !gateScopeID.MatchString(hostID) {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error { var e error; out, e = r.resolveHostAdmission(ctx, tx, hostID); return e })
	return
}
func (r *GateRepository) CheckHostAdmission(ctx context.Context, hostID, purpose string, at time.Time) (HostAdmissionSnapshot, error) {
	if !slices.Contains([]string{"baseline-install", "role-install", "workload-admit", "workload-credential"}, purpose) || at.IsZero() {
		return HostAdmissionSnapshot{}, actionError(generated.ErrorCodeInputInvalid)
	}
	return r.ResolveHostAdmission(ctx, hostID)
}

// ValidateHostAdmissionBinding checks only target/declaration binding freshness.
// Admission-dependent reservations additionally require the common evaluator and
// the full proof-set comparison in their own write transaction.
func (r *GateRepository) ValidateHostAdmissionBinding(ctx context.Context, hostID, bindingDigest string, expected RevisionToken) error {
	if r == nil || r.store == nil {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	return r.store.Read(ctx, func(tx ReadTx) error {
		s, e := r.resolveHostAdmission(ctx, tx, hostID)
		if e != nil {
			return e
		}
		if s.BindingDigest != bindingDigest || s.Revision.RecoveryEpoch != expected.RecoveryEpoch || s.Revision.StateRevision < expected.StateRevision {
			return actionError(generated.ErrorCodePlanStale)
		}
		return nil
	})
}
func (r *GateRepository) resolveHostAdmission(ctx context.Context, tx ReadTx, hostID string) (out HostAdmissionSnapshot, err error) {
	row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
	if _, err = adoptionGrant(ctx, row, hostID, "host", "read", "host.read", false); err != nil {
		return
	}
	if out.Host, err = readManagedHost(row, hostID); err != nil {
		return
	}
	out.Bundles = map[string]generated.GateEvidenceBundle{}
	out.AppliedBindings = map[string]HostAppliedBinding{}
	out.PrerequisiteDigests = map[string]string{}
	out.PrerequisiteEvidenceIDs = map[string]string{}
	if err = row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&out.Revision.StateRevision, &out.Revision.RecoveryEpoch); err != nil {
		return
	}
	if err = row(`SELECT identity_digest FROM managed_hosts WHERE host_id=?`, hostID).Scan(&out.IdentityDigest); err != nil {
		return
	}
	if out.Host.RecoveryEpoch != out.Revision.RecoveryEpoch {
		out.Blockers = append(out.Blockers, "host-binding-changed")
	}
	target, e := discoveryTarget(row, out.Host.TargetID)
	if e != nil {
		out.Blockers = append(out.Blockers, "host-binding-changed")
	} else {
		out.Profile = generated.HostProfile{Schema: generated.SchemaIDHostProfile, SchemaVersion: "1.0.0", ProfileID: out.Host.ProfileID, OSFamily: target.Binding.ExpectedOS, OSVersion: target.Binding.ExpectedVersion, Architecture: target.Binding.ExpectedArchitecture, RoleID: "host", DefinitionVersion: "1.0.0"}
	}
	if err = r.admissionMeasurements(ctx, tx, &out); err != nil {
		return
	}
	if err = admissionMutationInvalidation(ctx, tx, &out); err != nil {
		return
	}
	if err = admissionVolumeDeclarations(ctx, tx, &out, r.store.config.Clock()); err != nil {
		return
	}
	if out.ProfileLockDigest == "" {
		out.Blockers = append(out.Blockers, "host-control-missing")
	}
	out.BindingDigest = hostaction.Digest(struct {
		Host        generated.ManagedHost
		Identity    string
		Target      any
		Profile     generated.HostProfile
		Lock        string
		Declaration string
		Revision    int64
		Volumes     []string
	}{out.Host, out.IdentityDigest, target, out.Profile, out.ProfileLockDigest, out.DeclarationID, out.DeclarationRevision, out.VolumeIDs})
	if err = r.admissionEvidence(ctx, tx, &out); err != nil {
		return
	}
	return
}

func (r *GateRepository) admissionMeasurements(ctx context.Context, tx ReadTx, out *HostAdmissionSnapshot) error {
	rows, e := tx.query(ctx, `SELECT c.control_bytes,c.measurement_bytes,c.result_bytes,p.canonical_bytes,e.canonical_bytes,p.readable_plan FROM host_control_results c JOIN immutable_plans p ON p.plan_id=c.plan_id AND p.plan_digest=c.plan_digest JOIN execution_receipts e ON e.receipt_id=c.receipt_id AND e.result_digest=c.result_digest AND e.status='succeeded' JOIN plan_run_steps s ON s.run_id=c.run_id AND s.step_id=c.step_id AND s.status='succeeded' AND s.effect_state='verified' WHERE c.host_id=? AND c.host_identity_digest=? AND c.recovery_epoch=? ORDER BY c.observed_at DESC,c.rowid DESC LIMIT 257`, out.Host.HostID, out.IdentityDigest, out.Revision.RecoveryEpoch)
	if e != nil {
		return e
	}
	var pending [][6][]byte
	for rows.Next() {
		var b [6][]byte
		if e = rows.Scan(&b[0], &b[1], &b[2], &b[3], &b[4], &b[5]); e != nil {
			rows.Close()
			return e
		}
		pending = append(pending, b)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if len(pending) > 256 {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	seen := map[string]bool{}
	row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
	for _, b := range pending {
		var v HostAdmissionMeasurement
		if json.Unmarshal(b[0], &v.Control) != nil || json.Unmarshal(b[1], &v.Measurement) != nil || json.Unmarshal(b[2], &v.Result) != nil || json.Unmarshal(b[3], &v.Plan) != nil || json.Unmarshal(b[4], &v.Receipt) != nil || generated.ValidateContractJSON(generated.SchemaIDHostControlResult, b[0], generated.ContractExact) != nil || hostaction.ValidateResult(v.Result) != nil || v.Result.ResultDigest != v.Receipt.ResultDigest || v.Control.ActionReceiptDigest != hostaction.BytesDigest(b[4]) || v.Measurement.MeasurementDigest != hostaction.MeasurementDigest(v.Measurement) || v.Control.MeasurementDigest != v.Measurement.MeasurementDigest {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		found := false
		for _, m := range v.Result.ControlMeasurements {
			found = found || hostaction.Digest(m) == hostaction.Digest(v.Measurement)
		}
		if !found {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if !validPlanDigests(v.Plan, string(b[5])) {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if v.Control.HostID != out.Host.HostID || v.Control.IdentityDigest != out.IdentityDigest || v.Control.RecoveryEpoch != out.Revision.RecoveryEpoch || v.Measurement.SubjectHostID != out.Host.HostID || v.Measurement.SubjectIdentityDigest != out.IdentityDigest || v.Control.ControlID != v.Measurement.ControlID || v.Control.Status != v.Measurement.Status || v.Control.ProducerID != v.Measurement.ProducerID || v.Control.ProducerVersion != v.Measurement.ProducerVersion || v.Control.DeclarationID != v.Plan.DeclarationID || v.Control.DeclarationRevision != v.Plan.Binding.DeclarationRevision || v.Receipt.PlanDigest != v.Plan.PlanDigest || v.Receipt.RecoveryEpoch != out.Revision.RecoveryEpoch {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if seen[v.Control.ControlID] {
			continue
		}
		seen[v.Control.ControlID] = true
		var declarationRaw []byte
		var reason string
		var declaration generated.DeclarationRevision
		if row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? ORDER BY declaration_revision DESC LIMIT 1`, v.Plan.DeclarationID).Scan(&declarationRaw, &reason) != nil || !decodeStoredDeclaration(declarationRaw, reason, &declaration) || declaration.Revision != v.Plan.Binding.DeclarationRevision || declaration.RecoveryEpoch != out.Revision.RecoveryEpoch || declaration.Status == "superseded" {
			out.Blockers = append(out.Blockers, "host-binding-changed")
			continue
		}

		if validateAccessCurrentTargets(row, v.Plan, r.store.config.Clock()) != nil {
			out.Blockers = append(out.Blockers, "host-binding-changed")
			continue
		}
		if v.Plan.HostBaselineScope != nil {
			if validateBaselineCurrent(row, v.Plan, r.store.config.Clock()) != nil {
				out.Blockers = append(out.Blockers, "host-binding-changed")
				continue
			}
			if out.ProfileLockDigest == "" && v.Plan.HostAction.ActionID != "debian.volume-recovery.verify" {
				in, err := debianbaseline.DecodeInput([]byte(v.Plan.HostAction.ActionInput))
				if err != nil {
					return err
				}
				out.ProfileLock = in.ProfileLock
				out.ProfileLockDigest = in.ProfileLockDigest
				out.Profile.RoleID = in.RoleID
				out.Profile.OSFamily = in.ProfileLock.OSFamily
				out.Profile.OSVersion = in.ProfileLock.OSVersion
				out.Profile.Architecture = in.ProfileLock.Architecture
				out.DeclarationID = v.Plan.DeclarationID
				out.DeclarationRevision = v.Plan.Binding.DeclarationRevision
				for _, volume := range in.Volumes {
					out.VolumeIDs = append(out.VolumeIDs, volume.VolumeID)
				}
			}
		}
		out.Results = append(out.Results, v.Control)
		out.Measurements = append(out.Measurements, v)
		out.ActionReceiptDigests = append(out.ActionReceiptDigests, v.Control.ActionReceiptDigest)
	}
	return nil
}

func (r *GateRepository) admissionEvidence(ctx context.Context, tx ReadTx, out *HostAdmissionSnapshot) error {
	rows, e := tx.query(ctx, `SELECT e.canonical_bytes,d.bundle_bytes,p.canonical_bytes,x.canonical_bytes,d.artifact_digest,p.readable_plan FROM gate_applied_evidence e JOIN gate_evidence_drafts d ON d.draft_id=e.draft_id JOIN immutable_plans p ON p.plan_id=e.plan_id AND p.plan_digest=e.plan_digest JOIN execution_receipts x ON x.run_id=e.run_id AND x.step_id=e.step_id AND x.status='succeeded' JOIN plan_run_steps s ON s.run_id=e.run_id AND s.step_id=e.step_id AND s.status='succeeded' AND s.effect_state='verified' WHERE e.subject_id=? AND e.status='applied' AND e.recovery_epoch=? AND e.state_revision<=? AND NOT EXISTS(SELECT 1 FROM gate_applied_evidence later WHERE later.recovery_epoch=e.recovery_epoch AND (later.supersedes_evidence_id=e.evidence_id OR later.revokes_evidence_id=e.evidence_id)) ORDER BY e.state_revision DESC LIMIT 65`, out.Host.HostID, out.Revision.RecoveryEpoch, out.Revision.StateRevision)
	if e != nil {
		return e
	}
	defer rows.Close()
	seenProof := map[string]bool{}
	blockedProofGates := map[string]bool{}
	for rows.Next() {
		var raw, bundleRaw, planRaw, receiptRaw []byte
		var draftArtifact, readablePlan string
		var ev generated.GateEvidence
		var b generated.GateEvidenceBundle
		var p generated.Plan
		var receipt generated.ExecutionReceipt
		if rows.Scan(&raw, &bundleRaw, &planRaw, &receiptRaw, &draftArtifact, &readablePlan) != nil || json.Unmarshal(raw, &ev) != nil || json.Unmarshal(bundleRaw, &b) != nil || json.Unmarshal(planRaw, &p) != nil || json.Unmarshal(receiptRaw, &receipt) != nil || generated.ValidateContractJSON(generated.SchemaIDGateEvidence, raw, generated.ContractExact) != nil || generated.ValidateContractJSON(generated.SchemaIDGateEvidenceBundle, bundleRaw, generated.ContractExact) != nil || ev.BundleDigest != hostaction.BytesDigest(bundleRaw) || receipt.PlanDigest != p.PlanDigest || receipt.RecoveryEpoch != out.Revision.RecoveryEpoch {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if !validPlanDigests(p, readablePlan) {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if ev.ReleaseBuildID != r.store.config.BuildVersion || ev.ToolVersion != r.store.config.ToolVersion || p.Binding.ToolVersion != r.store.config.ToolVersion {
			out.Blockers = append(out.Blockers, "host-binding-changed")
			continue
		}
		var declarationRaw []byte
		var reason string
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? ORDER BY declaration_revision DESC LIMIT 1`, p.DeclarationID).Scan(&declarationRaw, &reason) != nil {
			out.Blockers = append(out.Blockers, "host-binding-changed")
			continue
		}
		var declaration generated.DeclarationRevision
		if !decodeStoredDeclaration(declarationRaw, reason, &declaration) || declaration.Revision != p.Binding.DeclarationRevision || declaration.RecoveryEpoch != out.Revision.RecoveryEpoch || declaration.Status == "superseded" {
			out.Blockers = append(out.Blockers, "host-binding-changed")
			continue
		}
		exact := false
		for _, op := range p.Operations {
			if op.OperationID == receipt.OperationID && op.TargetID == out.Host.HostID && op.AdapterID == "core.gate" && slices.Contains([]string{"gate.evidence.apply", "gate.evidence.supersede"}, op.OperationType) && op.InputDigest == ev.BundleDigest && op.ArtifactDigest == ev.BundleDigest && receipt.ArtifactDigest == op.ArtifactDigest {
				exact = true
			}
		}
		if !exact || ev.DeclarationID != p.DeclarationID || ev.DeclarationRevision != p.Binding.DeclarationRevision || ev.ArtifactDigest != draftArtifact {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if len(out.Evidence) >= 64 {
			return actionError(generated.ErrorCodeInputInvalid)
		}
		out.Evidence = append(out.Evidence, ev)
		out.Bundles[ev.EvidenceID] = b
		out.AppliedBindings[ev.EvidenceID] = HostAppliedBinding{DeclarationID: p.DeclarationID, DeclarationRevision: declaration.Revision, ArtifactDigest: draftArtifact, BundleDigest: ev.BundleDigest, StateRevision: ev.StateRevision, RecoveryEpoch: ev.RecoveryEpoch, ReleaseBuildID: r.store.config.BuildVersion, ToolVersion: p.Binding.ToolVersion}
		if r.hostProvenance != nil && !blockedProofGates[ev.GateID] {
			proof, err := r.hostProvenance.VerifyHostEvidence(*out, ev, b)
			if err != nil {
				blockedProofGates[ev.GateID] = true
				continue
			}
			if proof.Qualification != nil {
				q := *proof.Qualification
				if seenProof["qualification:"+q.Stage] {
					continue
				}
				seenProof["qualification:"+q.Stage] = true
				if q.EvidenceID != ev.EvidenceID || q.ProfileDigest != out.ProfileLockDigest || q.RecoveryEpoch != out.Revision.RecoveryEpoch || !slices.Contains([]string{"baseline", "role", "recovery"}, q.Stage) {
					return actionError(generated.ErrorCodeIntegrityFailure)
				}
				out.Qualifications = append(out.Qualifications, q)
				out.QualificationDigests = append(out.QualificationDigests, ev.BundleDigest)
			}
			if proof.PrerequisiteID != "" {
				if !slices.Contains([]string{"identity-console", "recovery-access", "physical-capacity", "physical-thermal-power", "qualified-virtual"}, proof.PrerequisiteID) || proof.PrerequisiteDigest == "" {
					return actionError(generated.ErrorCodeIntegrityFailure)
				}
				if _, exists := out.PrerequisiteDigests[proof.PrerequisiteID]; exists {
					continue
				}
				out.PrerequisiteDigests[proof.PrerequisiteID] = proof.PrerequisiteDigest
				out.PrerequisiteEvidenceIDs[proof.PrerequisiteID] = ev.EvidenceID
			}
		}
	}
	return rows.Err()
}

func admissionVolumeDeclarations(ctx context.Context, tx ReadTx, out *HostAdmissionSnapshot, at time.Time) error {
	rows, e := tx.query(ctx, `SELECT d.canonical_bytes,d.reason_digest FROM declaration_revisions d WHERE d.declaration_type='host.volume' AND d.recovery_epoch=? AND NOT EXISTS(SELECT 1 FROM declaration_revisions n WHERE n.declaration_id=d.declaration_id AND n.declaration_revision>d.declaration_revision) LIMIT 257`, out.Revision.RecoveryEpoch)
	if e != nil {
		return e
	}
	var declarations []generated.DeclarationRevision
	for rows.Next() {
		var raw []byte
		var reason string
		var d generated.DeclarationRevision
		if rows.Scan(&raw, &reason) != nil || !decodeStoredDeclaration(raw, reason, &d) {
			rows.Close()
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		declarations = append(declarations, d)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if len(declarations) > 256 {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	volumes := map[string]bool{}
	for _, d := range declarations {
		subject := false
		for _, op := range d.Operations {
			subject = subject || op.TargetID == out.Host.HostID
		}
		if !subject || d.Status == "superseded" {
			continue
		}
		found := false
		for _, m := range out.Measurements {
			if m.Measurement.Volume != nil {
				b := m.Measurement.Volume.Binding
				if b.DeclarationID == d.DeclarationID && b.DeclarationRevision == d.Revision {
					found = true
					volumes[b.VolumeID] = true
				}
			}
		}
		if !found {
			out.Blockers = append(out.Blockers, "host-storage-declaration-unverified")
		}
	}
	out.VolumeIDs = nil
	for v := range volumes {
		out.VolumeIDs = append(out.VolumeIDs, v)
	}
	slices.Sort(out.VolumeIDs)
	if len(out.VolumeIDs) > 16 {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	if len(out.VolumeIDs) > 0 {
		if e = resolveHostStoragePrerequisites(ctx, tx, out.Host.HostID, out.VolumeIDs, at, &out.Storage); e != nil {
			out.Blockers = append(out.Blockers, "host-storage-recovery-missing")
		}
	}
	return nil
}

// ValidateHostAdmissionSnapshot compares only the relevant bounded proof set.
// It does not decide admission or reserve an action. A future reservation writer
// must call the transaction-level helper in its own write transaction, alongside
// the common evaluator and current authorization checks.
func (r *GateRepository) ValidateHostAdmissionSnapshot(ctx context.Context, expected HostAdmissionSnapshot) error {
	if r == nil || r.store == nil || expected.Host.HostID == "" {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	return r.store.Read(ctx, func(tx ReadTx) error { return r.validateHostAdmissionSnapshot(ctx, tx, expected) })
}
func (r *GateRepository) validateHostAdmissionSnapshot(ctx context.Context, tx ReadTx, expected HostAdmissionSnapshot) error {
	current, e := r.resolveHostAdmission(ctx, tx, expected.Host.HostID)
	if e != nil {
		return e
	}
	if hostAdmissionProofDigest(current) != hostAdmissionProofDigest(expected) {
		return actionError(generated.ErrorCodePlanStale)
	}
	return nil
}
func hostAdmissionProofDigest(s HostAdmissionSnapshot) string {
	// Global revision deliberately excluded: unrelated writes are not host drift.
	return hostaction.Digest(struct {
		Binding, RoleBinding string
		Epoch                int64
		Measurements         []HostAdmissionMeasurement
		Evidence             []generated.GateEvidence
		Qualifications       []HostNativeQualification
		Prerequisites        map[string]string
		Storage              HostStoragePrerequisites
		Blockers             []string
	}{s.BindingDigest, s.RoleBindingDigest, s.Revision.RecoveryEpoch, s.Measurements, s.Evidence, s.Qualifications, s.PrerequisiteDigests, s.Storage, s.Blockers})
}

// A later attempted mutation invalidates earlier measurements even if it failed
// before verification and used a different declaration ID. Inert drafts and
// read-only collectors do not enter this query.
func admissionMutationInvalidation(ctx context.Context, tx ReadTx, out *HostAdmissionSnapshot) error {
	if len(out.Measurements) == 0 {
		return nil
	}
	oldest := out.Measurements[0].Plan.Binding.StateRevision
	for _, m := range out.Measurements {
		if m.Plan.Binding.StateRevision < oldest {
			oldest = m.Plan.Binding.StateRevision
		}
	}
	rows, e := tx.query(ctx, `SELECT DISTINCT p.canonical_bytes,p.readable_plan FROM immutable_plans p JOIN plan_runs r ON r.plan_id=p.plan_id AND r.plan_digest=p.plan_digest JOIN plan_run_steps s ON s.run_id=r.run_id WHERE r.recovery_epoch=? AND s.operation_type='host.action.execute' AND s.effect_state IN ('intent-recorded','receipt-recorded','effect-unknown','verified') AND s.target_id=? AND p.state_revision>? ORDER BY p.state_revision DESC LIMIT 65`, out.Revision.RecoveryEpoch, out.Host.HostID, oldest)
	if e != nil {
		return e
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var raw []byte
		var readable string
		var p generated.Plan
		if rows.Scan(&raw, &readable) != nil || json.Unmarshal(raw, &p) != nil || !validPlanDigests(p, readable) {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		count++
		if count > 64 {
			return actionError(generated.ErrorCodeInputInvalid)
		}
		for _, m := range out.Measurements {
			if hostMutationInvalidates(p, m, out.Host.HostID) {
				out.Blockers = append(out.Blockers, "host-binding-changed")
				return nil
			}
		}
	}
	return rows.Err()
}
func hostMutationInvalidates(p generated.Plan, m HostAdmissionMeasurement, hostID string) bool {
	if p.PlanID == m.Plan.PlanID || p.Binding.StateRevision <= m.Plan.Binding.StateRevision {
		return false
	}
	if p.HostAccessSequence != nil && p.HostAccessSequence.SubjectHostID == hostID {
		return m.Control.ProducerID == "debian-access-native" || m.Control.ProducerID == "debian-access-probe"
	}
	if p.HostAction == nil || p.HostAction.HostID != hostID {
		return false
	}
	switch p.HostAction.ActionID {
	case "debian.access.apply":
		return m.Control.ProducerID == "debian-access-native" || m.Control.ProducerID == "debian-access-probe"
	case "debian.baseline.apply", "debian.aide.initialize", "debian.aide.refresh":
		return p.HostBaselineScope != nil && p.HostBaselineScope.SubjectHostID == hostID && slices.Contains(p.HostBaselineScope.ControlIDs, m.Control.ControlID)
	}
	return false
}
