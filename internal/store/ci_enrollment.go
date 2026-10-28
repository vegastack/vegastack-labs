package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

type CIEnrollmentRepository struct{ store *Store }

func NewCIEnrollmentRepository(s *Store) *CIEnrollmentRepository { return &CIEnrollmentRepository{s} }
func ciEnrollmentDeclarationID(id string) string {
	return "ci-enrollment-" + ciEnrollmentDigest(id)[7:39]
}

type CIEnrollmentPolicy struct {
	Definition        generated.CiEnrollmentDefinition
	Binding           generated.CiEnrollmentBinding
	ResourceKeyDigest string
}

func normalizeCIEnrollmentPolicies(c *Config) error {
	bindings := make([]generated.CiEnrollmentBinding, 0, len(c.CIEnrollmentPolicies))
	for _, p := range c.CIEnrollmentPolicies {
		bindings = append(bindings, p.Binding)
	}
	frozen, err := serverconfig.FreezeCIEnrollmentBindings(bindings)
	if err != nil {
		return err
	}
	out := make([]CIEnrollmentPolicy, 0, len(frozen))
	for i, b := range frozen {
		p := c.CIEnrollmentPolicies[i]
		raw, _ := json.Marshal(p.Definition)
		if generated.ValidateContractJSON(generated.SchemaIDCiEnrollmentDefinition, raw, generated.ContractExact) != nil {
			return actionError(generated.ErrorCodeInputInvalid)
		}
		if ciEnrollmentDigest(b) != p.Definition.BindingDigest || p.Definition.EnrollmentID != b.EnrollmentID || p.Definition.BindingID != b.BindingID || p.Definition.OwnerID != b.OwnerID || p.ResourceKeyDigest != CIEnrollmentPolicyKey(b) {
			return actionError(generated.ErrorCodeInputInvalid)
		}
		p.Binding = b
		out = append(out, p)
	}
	c.CIEnrollmentPolicies = out
	return nil
}
func CIEnrollmentPolicyKey(b generated.CiEnrollmentBinding) string {
	b.EnrollmentID = ""
	b.BindingID = ""
	b.OwnerID = ""
	return ciEnrollmentDigest(b)
}
func (r *CIEnrollmentRepository) policy(d generated.CiEnrollmentDefinition) (CIEnrollmentPolicy, error) {
	if r == nil || r.store == nil {
		return CIEnrollmentPolicy{}, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	for _, p := range r.store.config.CIEnrollmentPolicies {
		if p.Definition == d {
			return p, nil
		}
	}
	return CIEnrollmentPolicy{}, actionError(generated.ErrorCodePlanStale)
}
func (r *CIEnrollmentRepository) authorize(p identity.Principal, row discoveryRow, d generated.CiEnrollmentDefinition, action, cap string) error {
	var current int
	if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN read_principals r ON r.principal_id=p.principal_id WHERE p.principal_id=? AND p.principal_kind=? AND p.status='active' AND r.status='active'`, p.ID, string(identity.EffectivePrincipalKind(p))).Scan(&current) != nil || current != 1 {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	if _, err := adoptionPrincipalGrant(p, row, d.EnrollmentID, "ci-enrollment", action, cap, false); err != nil {
		return err
	}
	if err := authorizeDeviceRow(row, p); err != nil {
		return err
	}
	if _, err := r.policy(d); err != nil {
		return err
	}
	var n int
	if row(`SELECT COUNT(*) FROM effective_authorization_principals WHERE principal_id=? AND status='active'`, d.OwnerID).Scan(&n) != nil || n != 1 {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	var epoch int64
	if row(`SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&epoch) != nil {
		return actionError(generated.ErrorCodePlanStale)
	}

	return nil
}
func (r *CIEnrollmentRepository) validate(p identity.Principal, row discoveryRow, in generated.CiEnrollmentRequest) error {
	if err := validateCIEnrollmentRequest(in); err != nil {
		return err
	}
	if err := r.authorize(p, row, in.Definition, "author", "ci.enrollment.prepare"); err != nil {
		return err
	}
	policy, _ := r.policy(in.Definition)
	var n int
	if row(`SELECT COUNT(*) FROM ci_enrollments WHERE enrollment_id=? OR resource_key_digest=?`, in.Definition.EnrollmentID, policy.ResourceKeyDigest).Scan(&n) != nil || n != 0 {
		return actionError(generated.ErrorCodeStateConflict)
	}
	return nil
}
func (r *CIEnrollmentRepository) Prepare(ctx context.Context, in generated.CiEnrollmentDraftRequest) (out generated.CiEnrollmentRequest, err error) {
	raw, _ := json.Marshal(in)
	if generated.ValidateContractJSON(generated.SchemaIDCiEnrollmentDraftRequest, raw, generated.ContractExact) != nil {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	p, err := serviceActor(ctx)
	if err != nil {
		return out, err
	}
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	var d generated.CiEnrollmentDefinition
	for _, policy := range r.store.config.CIEnrollmentPolicies {
		if policy.Definition.EnrollmentID == in.EnrollmentID && policy.Definition.BindingID == in.BindingID {
			d = policy.Definition
		}
	}
	out = generated.CiEnrollmentRequest{Schema: generated.SchemaIDCiEnrollmentRequest, SchemaVersion: "1.0.0", Definition: d, ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, IdempotencyKey: in.IdempotencyKey, ReasonDigest: in.ReasonDigest}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		var s, e int64
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&s, &e) != nil || s != in.ExpectedStateRevision || e != in.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		return r.validate(p, row, out)
	})
	return
}
func (r *CIEnrollmentRepository) Stage(ctx context.Context, in generated.CiEnrollmentRequest) (out generated.DeclarationRevisionRequest, err error) {
	p, err := serviceActor(ctx)
	if err != nil {
		return out, err
	}
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		var s, e int64
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&s, &e) != nil || s != in.ExpectedStateRevision || e != in.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		return r.validate(p, row, in)
	})
	if err != nil {
		return out, err
	}
	digest := ciEnrollmentDigest(in)
	return generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", CIEnrollment: &in, DeclarationID: ciEnrollmentDeclarationID(in.Definition.EnrollmentID), DeclarationType: "ci.enrollment.register", ExpectedRevision: 1, ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, ReasonDigest: in.ReasonDigest, Extensions: []generated.ContractExtension{}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: ciEnrollmentOperationID, OperationType: ciEnrollmentOperation, AdapterID: ciEnrollmentAdapterID, TargetID: in.Definition.EnrollmentID, InputDigest: digest, ArtifactDigest: digest, Idempotent: false}}}, nil
}
func ValidateCIEnrollmentDeclaration(d generated.DeclarationRevision) bool {
	present := d.CIEnrollment != nil || d.DeclarationType == "ci.enrollment.register"
	for _, op := range d.Operations {
		present = present || op.AdapterID == ciEnrollmentAdapterID
	}
	if !present {
		return true
	}
	in := d.CIEnrollment
	if in == nil || validateCIEnrollmentRequest(*in) != nil || d.HostingLifecycle != nil || d.ServiceRecovery != nil || d.ServiceDeployment != nil || d.ServiceImport != nil || d.NetworkEndpoint != nil || d.AuthorizationGrantBatch != nil || d.HostAliasClaim != nil || d.DeclarationType != "ci.enrollment.register" || d.DeclarationID != ciEnrollmentDeclarationID(in.Definition.EnrollmentID) || len(d.Operations) != 1 || len(d.Extensions) != 0 || d.RecoveryEpoch != in.RecoveryEpoch {
		return false
	}
	if d.Status == "draft" && (d.StateRevision != in.ExpectedStateRevision+1 || d.Revision != 1) {
		return false
	}
	op := d.Operations[0]
	return op.Sequence == 1 && op.OperationID == ciEnrollmentOperationID && op.OperationType == ciEnrollmentOperation && op.AdapterID == ciEnrollmentAdapterID && op.TargetID == in.Definition.EnrollmentID && op.InputDigest == ciEnrollmentDigest(in) && op.ArtifactDigest == op.InputDigest && !op.Idempotent && op.OffsiteRunSpec == nil
}
func readCIEnrollment(row discoveryRow, id string) (out generated.CiEnrollmentRecord, err error) {
	var raw []byte
	var digest, bindingDigest string
	var binding []byte
	if err = row(`SELECT canonical_bytes,digest,binding_bytes,binding_digest FROM ci_enrollments WHERE enrollment_id=?`, id).Scan(&raw, &digest, &binding, &bindingDigest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = actionError(generated.ErrorCodeResourceNotFound)
		}
		return
	}
	if json.Unmarshal(raw, &out) != nil || generated.ValidateContractJSON(generated.SchemaIDCiEnrollmentRecord, raw, generated.ContractExact) != nil || out.Definition.EnrollmentID != id || ciEnrollmentDigest(out) != digest || ciEnrollmentDigest(json.RawMessage(binding)) != bindingDigest || out.Definition.BindingDigest != bindingDigest {
		return out, actionError(generated.ErrorCodeIntegrityFailure)
	}
	return
}
func (r *CIEnrollmentRepository) Get(ctx context.Context, id string) (out generated.CiEnrollmentRecord, err error) {
	if !principal.ValidID(id) {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	p, err := serviceActor(ctx)
	if err != nil {
		return out, err
	}
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if err := authorizeDeviceRow(row, p); err != nil {
			return err
		}
		var active int
		if row(`SELECT COUNT(*) FROM read_principals WHERE principal_id=? AND status='active'`, p.ID).Scan(&active) != nil || active != 1 {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		if _, e := adoptionPrincipalGrant(p, row, id, "ci-enrollment", "read", "ci.enrollment.read", false); e != nil {
			return e
		}
		var e error
		out, e = readCIEnrollment(row, id)
		if e != nil {
			return e
		}
		var epoch int64
		if row(`SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&epoch) != nil || out.RecoveryEpoch != epoch {
			return actionError(generated.ErrorCodeRecoveryEpochMismatch)
		}
		return r.authorize(p, row, out.Definition, "read", "ci.enrollment.read")
	})
	if err != nil {
		out = generated.CiEnrollmentRecord{}
	}
	return
}
func (r *CIEnrollmentRepository) List(ctx context.Context, after string, limit int) (out generated.CiEnrollmentList, err error) {
	out = generated.CiEnrollmentList{Schema: generated.SchemaIDCiEnrollmentList, SchemaVersion: "1.0.0", Enrollments: []generated.CiEnrollmentRecord{}}
	if limit < 1 || limit > 100 || after != "" && !principal.ValidID(after) {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	p, err := serviceActor(ctx)
	if err != nil {
		return out, err
	}
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if e := authorizeDeviceRow(row, p); e != nil {
			return e
		}
		var n int
		if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision JOIN read_principals r ON r.principal_id=p.principal_id AND r.status='active' WHERE p.principal_id=? AND p.principal_kind=? AND p.status='active' AND g.status='active' AND g.action='read' AND g.capability='ci.enrollment.read' AND g.resource_kind='ci-enrollment'`, p.ID, string(identity.EffectivePrincipalKind(p))).Scan(&n) != nil || n == 0 {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		if e := row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&out.StateRevision, &out.RecoveryEpoch); e != nil {
			return e
		}
		rows, e := tx.query(ctx, `SELECT s.enrollment_id FROM ci_enrollments s WHERE s.enrollment_id>? AND EXISTS(SELECT 1 FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.principal_kind=? AND p.status='active' AND g.status='active' AND g.action='read' AND g.capability='ci.enrollment.read' AND g.resource_kind='ci-enrollment' AND g.resource_id=s.enrollment_id) ORDER BY s.enrollment_id LIMIT ?`, after, p.ID, string(identity.EffectivePrincipalKind(p)), limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		ids := []string{}
		for rows.Next() {
			var id string
			if e := rows.Scan(&id); e != nil {
				return e
			}
			ids = append(ids, id)
		}
		if e := rows.Err(); e != nil {
			return e
		}
		rows.Close()
		for _, id := range ids {
			v, e := readCIEnrollment(row, id)
			if e != nil {
				return e
			}
			if v.RecoveryEpoch != out.RecoveryEpoch {
				return actionError(generated.ErrorCodeRecoveryEpochMismatch)
			}
			if e = r.authorize(p, row, v.Definition, "read", "ci.enrollment.read"); e != nil {
				return e
			}
			if len(out.Enrollments) == limit {
				out.NextAfter = out.Enrollments[limit-1].Definition.EnrollmentID
				break
			}
			out.Enrollments = append(out.Enrollments, v)
		}
		return nil
	})
	if err != nil {
		out = generated.CiEnrollmentList{}
	}
	return
}

const ciEnrollmentOperationID = "ci-enrollment"
const ciEnrollmentOperation = "ci.enrollment.register"
const ciEnrollmentAdapterID = "core.ci-enrollment"

func ciEnrollmentDigest(v any) string { return hostaction.Digest(v) }
func validateCIEnrollmentRequest(in generated.CiEnrollmentRequest) error {
	raw, _ := json.Marshal(in)
	if generated.ValidateContractJSON(generated.SchemaIDCiEnrollmentRequest, raw, generated.ContractExact) != nil || in.ExpectedDeclarationRevision != 0 {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	return nil
}

// ExecutionPolicy exposes current private enrollment only to the protected
// executor composition after its authenticated read scope and applied history
// have been checked. Enrollment observation alone never authorizes a lease.
func (r *CIEnrollmentRepository) ExecutionPolicy(ctx context.Context, id string, expected RevisionToken) (out CIEnrollmentPolicy, err error) {
	actor, err := serviceActor(ctx)
	if err != nil {
		return out, err
	}
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		record, e := readCIEnrollment(row, id)
		if e != nil {
			return e
		}
		if e = r.authorize(actor, row, record.Definition, "read", "ci.enrollment.read"); e != nil {
			return e
		}
		if _, e = r.appliedPolicy(row, record.Definition, expected); e != nil {
			return e
		}
		out, e = r.policy(record.Definition)
		out.Binding.Labels = append([]string(nil), out.Binding.Labels...)
		return e
	})
	if err != nil {
		out = CIEnrollmentPolicy{}
	}
	return
}
