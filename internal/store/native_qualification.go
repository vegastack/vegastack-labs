package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

type nativeQuery struct {
	tx   ReadTx
	row  func(string, ...any) *sql.Row
	rows func(string, ...any) (*sql.Rows, error)
}

func nativeError() error { return actionError(generated.ErrorCodePrerequisiteBlocked) }
func nativeContract(schema string, v any) bool {
	raw, e := json.Marshal(v)
	return e == nil && generated.ValidateContractJSON(schema, raw, generated.ContractExact) == nil
}

func (r *GateRepository) ResolveNativeProducers(ctx context.Context, in generated.NativeCollectRequest) (out NativeProducerSnapshot, err error) {
	if r == nil || r.store == nil || !nativeContract(generated.SchemaIDNativeCollectRequest, in) || len(in.Producers) == 0 || len(in.Producers) > 48 {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		var e error
		out, e = r.resolveNativeProducers(ctx, nativeQuery{tx, func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }, func(q string, a ...any) (*sql.Rows, error) { return tx.query(ctx, q, a...) }}, in, true)
		return e
	})
	if err != nil {
		out = NativeProducerSnapshot{}
	}
	return
}
func (r *GateRepository) resolveNativeProducers(ctx context.Context, q nativeQuery, in generated.NativeCollectRequest, author bool) (out NativeProducerSnapshot, err error) {
	var mode string
	if err = q.row(`SELECT state_revision,recovery_epoch,instance_id,authority_mode FROM system_meta WHERE id=1`).Scan(&out.Revision.StateRevision, &out.Revision.RecoveryEpoch, &out.ControllerInstanceID, &mode); err != nil {
		return
	}
	if mode != "ready" {
		return out, nativeError()
	}
	if out.Revision.RecoveryEpoch != in.RecoveryEpoch || (author && out.Revision.StateRevision != in.ExpectedStateRevision) {
		return out, actionError(generated.ErrorCodePlanStale)
	}
	if author {
		if _, err = adoptionGrant(ctx, q.row, "native."+in.Stage, "gate", "author", "gate.evidence.author", true); err != nil {
			return
		}
		if _, err = adoptionGrant(ctx, q.row, "gate-evidence-"+in.EvidenceID, "declaration", "author", "declaration.author", true); err != nil {
			return
		}
	}
	if out.VerifiedRestoreBinding, err = nativeVerifiedRestoreBinding(ctx, q); err != nil {
		return out, err
	}
	seen := map[string]bool{}
	for _, ref := range in.Producers {
		key := ref.ScenarioID + ":" + ref.RunID + ":" + ref.StepID
		if seen[key] {
			return out, nativeError()
		}
		seen[key] = true
		if author {
			if _, err = adoptionGrant(ctx, q.row, ref.HostID, "host", "read", "host.read", false); err != nil {
				return
			}
		}
		var identity string
		if err = q.row(`SELECT identity_digest FROM managed_hosts WHERE host_id=?`, ref.HostID).Scan(&identity); err != nil {
			return out, nativeError()
		}
		var planRaw, receiptRaw []byte
		var readable, status, effect, leaseBinding, leaseNonce, leaseTarget, stepOperation, stepAdapter, stepExecutor, stepTarget, stepInput, stepArtifact, stepResult, runStatus string
		var leaseEpoch int64
		err = q.row(`SELECT p.canonical_bytes,p.readable_plan,x.canonical_bytes,s.status,s.effect_state,l.binding_digest,l.nonce_digest,l.target_id,l.recovery_epoch,s.operation_id,s.adapter_id,s.executor_id,s.target_id,s.input_digest,s.artifact_digest,COALESCE(s.result_digest,''),r.status FROM immutable_plans p JOIN plan_runs r ON r.plan_id=p.plan_id AND r.plan_digest=p.plan_digest JOIN plan_run_steps s ON s.run_id=r.run_id JOIN execution_receipts x ON x.run_id=r.run_id AND x.step_id=s.step_id JOIN target_execution_leases l ON l.lease_id=x.lease_id AND l.run_id=r.run_id AND l.step_id=s.step_id WHERE p.plan_id=? AND p.plan_digest=? AND r.run_id=? AND s.step_id=? AND x.lease_id=? AND x.status IN ('succeeded','failed','partial') AND l.status='released'`, ref.PlanID, ref.PlanDigest, ref.RunID, ref.StepID, ref.LeaseID).Scan(&planRaw, &readable, &receiptRaw, &status, &effect, &leaseBinding, &leaseNonce, &leaseTarget, &leaseEpoch, &stepOperation, &stepAdapter, &stepExecutor, &stepTarget, &stepInput, &stepArtifact, &stepResult, &runStatus)
		if err != nil {
			return out, nativeError()
		}
		var execution NativeProducerExecution
		execution.Reference = ref
		p, x := &execution.Plan, &execution.Receipt
		if json.Unmarshal(planRaw, p) != nil || json.Unmarshal(receiptRaw, x) != nil || !validPlanDigests(*p, readable) || !nativeContract(generated.SchemaIDExecutionReceipt, *x) || p.PlanID != ref.PlanID || p.PlanDigest != ref.PlanDigest || x.PlanID != ref.PlanID || x.PlanDigest != ref.PlanDigest || x.RunID != ref.RunID || x.StepID != ref.StepID || x.LeaseID != ref.LeaseID || x.RecoveryEpoch != p.Binding.RecoveryEpoch || x.BindingDigest != leaseBinding || x.NonceDigest != leaseNonce || x.TargetID != leaseTarget || x.RecoveryEpoch != leaseEpoch || x.ResultDigest != stepResult || status != x.Status || !(status == "succeeded" && effect == "verified" || status == "failed" && effect == "verified" && runStatus == "failed" || status == "partial" && effect == "verified" && runStatus == "partial" && nativePartialProducer(ref, *p)) {
			return out, nativeError()
		}
		if x.RecoveryEpoch != in.RecoveryEpoch {
			return out, nativeError()
		}
		exact := false
		for _, op := range p.Operations {
			if op.OperationID == x.OperationID && op.OperationID == stepOperation && op.AdapterID == x.AdapterID && op.AdapterID == stepAdapter && op.ExecutorID == x.ExecutorID && op.ExecutorID == stepExecutor && op.TargetID == x.TargetID && op.TargetID == stepTarget && op.InputDigest == stepInput && op.ArtifactDigest == stepArtifact && op.ArtifactDigest == x.ArtifactDigest {
				exact = true
			}
		}
		if !exact || p.Binding.ToolVersion != r.store.config.ToolVersion {
			return out, nativeError()
		}
		subjectID, subjectIdentity := ref.HostID, identity
		if p.HostAction != nil || p.HostAccessSequence != nil {
			draft, _, e := actionDraftForPlan(q.row, *p, x.OperationID)
			if e != nil || draft.Request.HostID != ref.HostID || draft.Request.ConsoleConfirmation.HostIdentityDigest != identity {
				return out, nativeError()
			}
			if p.HostAccessSequence != nil {
				subjectID, subjectIdentity = p.HostAccessSequence.SubjectHostID, p.HostAccessSequence.SubjectIdentityDigest
			} else if p.HostBaselineScope != nil {
				subjectID, subjectIdentity = p.HostBaselineScope.SubjectHostID, p.HostBaselineScope.SubjectIdentityDigest
			}
		} else if ref.ScenarioID == "native-credential-lifecycle" && x.AdapterID == "core.credential" {
			execution.Credential, err = r.nativeCredentialEvidence(ctx, q, execution, identity)
			if err != nil {
				return out, err
			}
		} else if p.HostReplacement != nil && in.Stage == "recovery" {
			execution.ReplacementRecovery, err = r.nativeReplacementRecoveryEvidence(ctx, q, execution)
			if err != nil {
				return out, err
			}
		} else {
			// Other lifecycle producers need their own exact historical identity
			// join; a current registration alone cannot establish that identity.
			return out, nativeError()
		}
		// Native sequence proofs retain each exact immutable declaration revision;
		// later fixture scenarios may legitimately revise the same declaration.
		var declarationRaw []byte
		var reason string
		if err = q.row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, p.DeclarationID, p.Binding.DeclarationRevision).Scan(&declarationRaw, &reason); err != nil {
			return out, nativeError()
		}
		var declaration generated.DeclarationRevision
		if !decodeStoredDeclaration(declarationRaw, reason, &declaration) || declaration.Revision != p.Binding.DeclarationRevision || declaration.RecoveryEpoch != p.Binding.RecoveryEpoch {
			return out, nativeError()
		}
		rows, e := q.rows(`SELECT control_bytes,measurement_bytes,result_bytes FROM host_control_results WHERE run_id=? AND step_id=? AND result_digest=? AND receipt_digest=? ORDER BY ordinal LIMIT 9`, ref.RunID, ref.StepID, x.ResultDigest, hostaction.BytesDigest(receiptRaw))
		if e != nil {
			return out, e
		}
		count := 0
		for rows.Next() {
			count++
			var cr, mr, rr []byte
			var measurement HostAdmissionMeasurement
			if rows.Scan(&cr, &mr, &rr) != nil || json.Unmarshal(cr, &measurement.Control) != nil || json.Unmarshal(mr, &measurement.Measurement) != nil || json.Unmarshal(rr, &measurement.Result) != nil || !nativeContract(generated.SchemaIDHostControlResult, measurement.Control) || hostaction.ValidateResult(measurement.Result) != nil || measurement.Result.ResultDigest != x.ResultDigest || measurement.Control.ActionReceiptDigest != hostaction.BytesDigest(receiptRaw) || measurement.Measurement.MeasurementDigest != hostaction.MeasurementDigest(measurement.Measurement) || measurement.Control.MeasurementDigest != measurement.Measurement.MeasurementDigest {
				rows.Close()
				return out, nativeError()
			}
			member := false
			for _, m := range measurement.Result.ControlMeasurements {
				member = member || hostaction.Digest(m) == hostaction.Digest(measurement.Measurement)
			}
			if !member || measurement.Control.HostID != subjectID || measurement.Control.IdentityDigest != subjectIdentity || measurement.Control.RecoveryEpoch != x.RecoveryEpoch || measurement.Measurement.SubjectHostID != subjectID || measurement.Measurement.SubjectIdentityDigest != subjectIdentity || measurement.Control.DeclarationID != p.DeclarationID || measurement.Control.DeclarationRevision != p.Binding.DeclarationRevision || measurement.Control.ControlID != measurement.Measurement.ControlID || measurement.Control.Status != measurement.Measurement.Status || measurement.Control.ProducerID != measurement.Measurement.ProducerID || measurement.Control.ProducerVersion != measurement.Measurement.ProducerVersion || measurement.Control.ObservedAt != measurement.Measurement.ObservedAt || measurement.Control.PositiveProbeDigest != measurement.Measurement.PositiveProbeDigest || measurement.Control.NegativeProbeDigest != measurement.Measurement.NegativeProbeDigest {
				rows.Close()
				return out, nativeError()
			}
			measurement.Plan = *p
			measurement.Receipt = *x
			if execution.Result != nil && hostaction.Digest(*execution.Result) != hostaction.Digest(measurement.Result) {
				rows.Close()
				return out, nativeError()
			}
			result := measurement.Result
			execution.Result = &result
			out.Measurements = append(out.Measurements, measurement)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, e
		}
		if count > 8 {
			return out, nativeError()
		}
		if ref.ScenarioID == "control-setup" || ref.ScenarioID == "control-handoff" && p.HostAction != nil && p.HostAction.ActionID == "debian.control.handoff.verify" && x.Status == "succeeded" {
			execution.ControlSetupAuthority, err = r.nativeControlSetupAuthority(ctx, q, execution)
			if err != nil {
				return out, err
			}
		}
		if x.Status == "partial" && (execution.Result == nil || execution.Result.Status != "partial") {
			return out, nativeError()
		}
		out.Executions = append(out.Executions, execution)
		out.Producers = append(out.Producers, generated.NativeQualificationProducer{Schema: generated.SchemaIDNativeQualificationProducer, SchemaVersion: "1.0.0", Reference: ref, HostIdentityDigest: identity, ReceiptDigest: hostaction.BytesDigest(receiptRaw)})
	}
	out.Digest = hostaction.Digest(out)
	return out, nil
}

func (r *GateRepository) PutNativeGateDraft(ctx context.Context, in NativeGateDraftRequest) (GateDraft, error) {
	var zero GateDraft
	if r == nil || r.store == nil || !nativeContract(generated.SchemaIDNativeCollectRequest, in.Request) || !nativeContract(generated.SchemaIDNativeQualification, in.Payload) || in.Bundle.NativeQualification == nil || hostaction.Digest(*in.Bundle.NativeQualification) != hostaction.Digest(in.Payload) || in.Payload.Stage != in.Request.Stage || in.Payload.ScopeDigest != in.Request.ScopeDigest || in.Payload.ProfileID != in.Request.ProfileID || in.Payload.RecoveryEpoch != in.Request.RecoveryEpoch || in.Bundle.CollectorID != "native-debian-228" || in.Bundle.ObservedAt != in.Payload.ObservedAt || !nativeBundleShape(in.Bundle, in.Payload) {
		return zero, nativeError()
	}
	observed, e := time.Parse(time.RFC3339, in.Payload.ObservedAt)
	expires, x := time.Parse(time.RFC3339, in.Payload.ExpiresAt)
	now := r.store.config.Clock().UTC()
	if e != nil || x != nil || observed.After(now.Add(time.Second)) || now.Sub(observed) > time.Minute || !expires.After(now) || expires.Sub(observed) > 24*time.Hour {
		return zero, nativeError()
	}
	if c := in.Payload.ControllerIdentity; c != nil && (c.ControllerInstanceID != in.Payload.ControllerInstanceID || c.ScopeDigest != in.Payload.ScopeDigest || c.ExecutableDigest != in.Payload.ExecutableDigest) {
		return zero, nativeError()
	}
	if hostaction.Digest(r.nativeController) != hostaction.Digest(in.Payload.ControllerIdentity) {
		return zero, nativeError()
	}
	snapshot, e := r.ResolveNativeProducers(ctx, in.Request)
	if e != nil {
		return zero, e
	}
	if snapshot.Digest != in.ResolvedDigest || snapshot.ControllerInstanceID != in.Payload.ControllerInstanceID || hostaction.Digest(snapshot.Producers) != hostaction.Digest(in.Payload.Producers) {
		return zero, nativeError()
	}
	var prerequisites []generated.NativeQualificationPrerequisite
	if e = r.store.Read(ctx, func(tx ReadTx) error {
		query := nativeQuery{tx, func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }, func(q string, a ...any) (*sql.Rows, error) { return tx.query(ctx, q, a...) }}
		var err error
		prerequisites, err = r.nativePrerequisites(ctx, query, in.Payload)
		return err
	}); e != nil {
		return zero, e
	}
	if len(in.Payload.Prerequisites) > 0 && !nativePrerequisitesEqual(in.Payload.Prerequisites, prerequisites) {
		return zero, nativeError()
	}
	in.Payload.Prerequisites = prerequisites
	in.Bundle.NativeQualification = &in.Payload
	for _, execution := range snapshot.Executions {
		if !NativeExecutionProfileMatches(execution, in.Payload.ProfileID, in.Payload.ProfileLockDigest) {
			return zero, nativeError()
		}
	}
	request := GateDraftRequest{EvidenceID: in.Request.EvidenceID, GateID: "native." + in.Request.Stage, SubjectID: in.Request.ProfileID, DefinitionVersion: "1.0.0", EvaluatorVersion: "1.0.0", SourceKind: "local", ProofClass: "live", ArtifactDigest: hostaction.Digest(in.Payload), Bundle: in.Bundle, Expected: snapshot.Revision, KeyDigest: hostaction.Digest(in.Request.IdempotencyKey), RequestDigest: hostaction.Digest(in.Request), Attribution: in.Attribution}
	return r.putGateDraft(ctx, request, &in)
}
func (r *GateRepository) validateNativeDraftTransaction(ctx context.Context, tx *sql.Tx, in NativeGateDraftRequest) error {
	q := nativeQuery{ReadTx{handle: tx}, func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }, func(q string, a ...any) (*sql.Rows, error) { return tx.QueryContext(ctx, q, a...) }}
	current, e := r.resolveNativeProducers(ctx, q, in.Request, true)
	if e != nil {
		return e
	}
	prerequisites, e := r.nativePrerequisites(ctx, q, in.Payload)
	if e != nil {
		return e
	}
	if !nativePrerequisitesEqual(in.Payload.Prerequisites, prerequisites) {
		return nativeError()
	}
	if current.Digest != in.ResolvedDigest || current.ControllerInstanceID != in.Payload.ControllerInstanceID || hostaction.Digest(current.Producers) != hostaction.Digest(in.Payload.Producers) {
		return nativeError()
	}
	return nil
}

func (r *GateRepository) resolveNativeApplied(ctx context.Context, tx ReadTx, s HostAdmissionSnapshot, e generated.GateEvidence, b generated.GateEvidenceBundle) (HostNativeProducerBinding, error) {
	var zero HostNativeProducerBinding
	p := b.NativeQualification
	if p == nil || !nativeContract(generated.SchemaIDNativeQualification, *p) || e.Status != "applied" || e.SubjectID != p.ProfileID || p.ProfileID != s.Profile.ProfileID || p.ProfileLockDigest != s.ProfileLockDigest || e.GateID != "native."+p.Stage || e.RecoveryEpoch != p.RecoveryEpoch || p.RecoveryEpoch != s.Revision.RecoveryEpoch || e.ArtifactDigest != hostaction.Digest(*p) || len(p.Producers) == 0 || len(p.Producers) > 48 {
		return zero, nativeError()
	}
	refs := make([]generated.NativeProducerReference, 0, len(p.Producers))
	for _, producer := range p.Producers {
		refs = append(refs, producer.Reference)
	}
	in := generated.NativeCollectRequest{Schema: generated.SchemaIDNativeCollectRequest, SchemaVersion: "1.0.0", ScopeDigest: p.ScopeDigest, Stage: p.Stage, EvidenceID: e.EvidenceID, ProfileID: p.ProfileID, Producers: refs, ExpectedStateRevision: s.Revision.StateRevision, RecoveryEpoch: s.Revision.RecoveryEpoch, IdempotencyKey: "native-durable-resolution"}
	query := nativeQuery{tx, func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }, func(q string, a ...any) (*sql.Rows, error) { return tx.query(ctx, q, a...) }}
	prerequisites, err := r.nativePrerequisites(ctx, query, *p)
	if err != nil || !nativePrerequisitesEqual(p.Prerequisites, prerequisites) {
		return zero, nativeError()
	}
	resolver := r
	if p.ControllerIdentity != nil {
		if p.ControllerIdentity.ControllerInstanceID != p.ControllerInstanceID || p.ControllerIdentity.ScopeDigest != p.ScopeDigest || p.ControllerIdentity.ExecutableDigest != p.ExecutableDigest {
			return zero, nativeError()
		}
		resolver = r.WithNativeControllerIdentity(*p.ControllerIdentity)
	}
	resolved, err := resolver.resolveNativeProducers(ctx, query, in, false)
	if err != nil || resolved.ControllerInstanceID != p.ControllerInstanceID || hostaction.Digest(resolved.Producers) != hostaction.Digest(p.Producers) {
		return zero, nativeError()
	}
	for _, execution := range resolved.Executions {
		if !NativeExecutionProfileMatches(execution, p.ProfileID, p.ProfileLockDigest) {
			return zero, nativeError()
		}
	}
	return HostNativeProducerBinding{CurrentControllerInstanceID: resolved.ControllerInstanceID, Qualification: *p, Applied: s.AppliedBindings[e.EvidenceID], Producers: resolved.Producers, Measurements: resolved.Measurements, Executions: resolved.Executions}, nil
}

// NativeExecutionProfileMatches binds measured configuration to the protected
// qualification profile, independently of a caller's report or gate facts.
func NativeExecutionProfileMatches(e NativeProducerExecution, profile, lock string) bool {
	p := e.Plan
	if e.Credential != nil {
		for _, v := range e.Credential.Verifications {
			if v.Result == "verified" && v.ProfileID != profile {
				return false
			}
		}
		return e.Credential.Controller.HostID == e.Reference.HostID
	}
	if e.ReplacementRecovery != nil {
		return e.ReplacementRecovery.CurrentProfileID == profile && e.ReplacementRecovery.CurrentProfileLockDigest == lock
	}
	if p.HostBaselineScope != nil {
		return p.HostBaselineScope.ProfileID == profile && p.HostBaselineScope.ProfileLockDigest == lock
	}
	if p.HostRoleScope != nil {
		return p.HostRoleScope.ProfileID == profile && p.HostRoleScope.ProfileLockDigest == lock
	}
	if p.HostAccessSequence != nil {
		return p.HostAccessSequence.ProfileLockDigest == lock
	}
	if p.HostAction != nil && (p.HostAction.ActionID == "debian.access.apply" || p.HostAction.ActionID == "debian.access.collect") {
		in, err := debianaccess.DecodeInput([]byte(p.HostAction.ActionInput))
		return err == nil && in.ProfileID == profile && in.ProfileLockDigest == lock
	}
	if e.Result != nil && len(e.Result.ControlMeasurements) > 0 {
		for _, m := range e.Result.ControlMeasurements {
			if m.ProfileLockDigest != lock {
				return false
			}
		}
		return true
	}
	return false
}

func nativeBundleShape(b generated.GateEvidenceBundle, p generated.NativeQualification) bool {
	if len(b.Attachments) != 0 || len(b.Facts) != 2 || len(b.Checks) != 1 {
		return false
	}
	facts := map[string]string{}
	for _, f := range b.Facts {
		if _, exists := facts[f.FactID]; exists {
			return false
		}
		facts[f.FactID] = f.ValueDigest
	}
	c := b.Checks[0]
	return facts["native.profile-lock"] == p.ProfileLockDigest && facts["native.source"] == p.SourceDigest && c.CheckID == "native."+p.Stage && c.VerifierVersion == "1.0.0" && c.Result == "passed" && c.ResultDigest == p.SourceDigest
}

func nativePartialProducer(ref generated.NativeProducerReference, p generated.Plan) bool {
	if p.HostAction == nil || p.HostRoleScope == nil {
		return false
	}
	if ref.ScenarioID == "control-handoff" {
		return p.HostAction.ActionID == "debian.control.handoff" && p.HostRoleScope.RoleID == "control"
	}
	if p.HostAction.ActionID != "debian.role.apply" {
		return false
	}
	want := map[string]string{"role-application": "application", "role-ci": "ci", "role-reserve": "reserve"}[ref.ScenarioID]
	return want != "" && p.HostRoleScope.RoleID == want
}
