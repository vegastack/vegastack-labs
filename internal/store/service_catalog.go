package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"regexp"
)

type ServiceRepository struct{ store *Store }

func NewServiceRepository(s *Store) *ServiceRepository { return &ServiceRepository{s} }
func serviceDeclarationID(id string) string {
	return "service-import-" + servicecatalog.Digest(id)[7:39]
}
func normalizeServicePolicies(c *Config) error {
	if len(c.ServiceImportPolicies) > 128 {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	ids, resources, bindings := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range c.ServiceImportPolicies {
		raw, _ := json.Marshal(p.Definition)
		if generated.ValidateContractJSON(generated.SchemaIDServiceDefinition, raw, generated.ContractExact) != nil || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(p.ResourceKeyDigest) || ids[p.Definition.ServiceID] || resources[p.ResourceKeyDigest] || bindings[p.Definition.BindingID] {
			return actionError(generated.ErrorCodeInputInvalid)
		}
		ids[p.Definition.ServiceID] = true
		resources[p.ResourceKeyDigest] = true
		bindings[p.Definition.BindingID] = true
	}
	c.ServiceImportPolicies = append([]servicecatalog.Policy(nil), c.ServiceImportPolicies...)
	return nil
}
func (r *ServiceRepository) policy(d generated.ServiceDefinition) (servicecatalog.Policy, error) {
	if r == nil || r.store == nil {
		return servicecatalog.Policy{}, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	for _, p := range r.store.config.ServiceImportPolicies {
		if p.Definition == d {
			return p, nil
		}
	}
	return servicecatalog.Policy{}, actionError(generated.ErrorCodePlanStale)
}
func (r *ServiceRepository) authorize(p identity.Principal, row discoveryRow, d generated.ServiceDefinition, action, cap string) error {
	var current int
	if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN read_principals r ON r.principal_id=p.principal_id WHERE p.principal_id=? AND p.principal_kind=? AND p.status='active' AND r.status='active'`, p.ID, string(identity.EffectivePrincipalKind(p))).Scan(&current) != nil || current != 1 {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	if _, err := adoptionPrincipalGrant(p, row, d.ServiceID, "service", action, cap, false); err != nil {
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
	if err := requireHostUnfrozen(row, d.HostID); err != nil {
		return err
	}
	var target, digest string
	var epoch, currentEpoch int64
	if row(`SELECT target_id,identity_digest,recovery_epoch FROM managed_hosts WHERE host_id=?`, d.HostID).Scan(&target, &digest, &epoch) != nil || digest != d.HostIdentityDigest {
		return actionError(generated.ErrorCodePlanStale)
	}
	if row(`SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&currentEpoch) != nil || epoch != currentEpoch {
		return actionError(generated.ErrorCodePlanStale)
	}
	// Follow trusted exclusions through aliases, historical owners and physical identities.
	for _, id := range r.store.config.NetworkConnectExcludedHostIDs {
		const hosts = `SELECT h.host_id FROM managed_hosts h WHERE h.host_id=?1 OR h.target_id=?1 OR h.host_id IN (SELECT owner_host_id FROM host_alias_owners WHERE alias_id=?1) OR h.identity_digest IN (SELECT owner_identity_digest FROM host_alias_owners WHERE alias_id=?1) OR h.host_id IN (SELECT owner_host_id FROM host_alias_history WHERE alias_id=?1) OR h.identity_digest IN (SELECT owner_identity_digest FROM host_alias_history WHERE alias_id=?1)`
		if row(`SELECT COUNT(*) FROM managed_hosts h WHERE h.host_id IN (`+hosts+`) AND (h.host_id=?2 OR h.identity_digest=?3 OR h.target_id=?4)`, id, d.HostID, d.HostIdentityDigest, target).Scan(&n) != nil || n != 0 {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
	}
	return nil
}
func (r *ServiceRepository) validate(p identity.Principal, row discoveryRow, in generated.ServiceImportRequest) error {
	if err := servicecatalog.ValidateImportRequest(in); err != nil {
		return err
	}
	if err := r.authorize(p, row, in.Definition, "author", "service.import.prepare"); err != nil {
		return err
	}
	policy, _ := r.policy(in.Definition)
	var n int
	if row(`SELECT COUNT(*) FROM service_catalog WHERE service_id=? OR resource_key_digest=?`, in.Definition.ServiceID, policy.ResourceKeyDigest).Scan(&n) != nil || n != 0 {
		return actionError(generated.ErrorCodeStateConflict)
	}
	return nil
}
func serviceActor(ctx context.Context) (identity.Principal, error) {
	p, ok := identity.PrincipalFromContext(ctx)
	if !ok || !identity.ValidPrincipal(p) {
		return p, actionError(generated.ErrorCodeAuthenticationRequired)
	}
	return p, nil
}
func (r *ServiceRepository) AuthorizeImport(ctx context.Context, d generated.ServiceDefinition) error {
	p, err := serviceActor(ctx)
	if err != nil {
		return err
	}
	if r == nil || r.store == nil {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	return r.store.Read(ctx, func(tx ReadTx) error {
		return r.authorize(p, func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }, d, "author", "service.import.prepare")
	})
}
func (r *ServiceRepository) Prepare(ctx context.Context, in generated.ServiceImportDraftRequest) (out generated.ServiceImportRequest, err error) {
	raw, _ := json.Marshal(in)
	if generated.ValidateContractJSON(generated.SchemaIDServiceImportDraftRequest, raw, generated.ContractExact) != nil {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	p, err := serviceActor(ctx)
	if err != nil {
		return out, err
	}
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	var d generated.ServiceDefinition
	for _, policy := range r.store.config.ServiceImportPolicies {
		if policy.Definition.ServiceID == in.ServiceID && policy.Definition.BindingID == in.BindingID {
			d = policy.Definition
		}
	}
	out = generated.ServiceImportRequest{Schema: generated.SchemaIDServiceImportRequest, SchemaVersion: "1.0.0", Definition: d, ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, IdempotencyKey: in.IdempotencyKey, ReasonDigest: in.ReasonDigest, ObservationDigest: servicecatalog.Digest("pending")}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		var s, e int64
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&s, &e) != nil || s != in.ExpectedStateRevision || e != in.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		return r.validate(p, row, out)
	})
	out.ObservationDigest = ""
	return
}
func (r *ServiceRepository) Stage(ctx context.Context, in generated.ServiceImportRequest) (out generated.DeclarationRevisionRequest, err error) {
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
	digest := servicecatalog.Digest(in)
	return generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", ServiceImport: &in, DeclarationID: serviceDeclarationID(in.Definition.ServiceID), DeclarationType: "service.import", ExpectedRevision: 1, ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, ReasonDigest: in.ReasonDigest, Extensions: []generated.ContractExtension{}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: servicecatalog.OperationID, OperationType: servicecatalog.Operation, AdapterID: servicecatalog.AdapterID, TargetID: in.Definition.ServiceID, InputDigest: digest, ArtifactDigest: digest, Idempotent: false}}}, nil
}
func ValidateServiceImportDeclaration(d generated.DeclarationRevision) bool {
	present := d.ServiceImport != nil || d.DeclarationType == "service.import"
	for _, op := range d.Operations {
		present = present || op.AdapterID == servicecatalog.AdapterID
	}
	if !present {
		return true
	}
	in := d.ServiceImport
	if in == nil || servicecatalog.ValidateImportRequest(*in) != nil || d.ServiceDeployment != nil || d.NetworkEndpoint != nil || d.AuthorizationGrantBatch != nil || d.HostAliasClaim != nil || d.DeclarationType != "service.import" || d.DeclarationID != serviceDeclarationID(in.Definition.ServiceID) || len(d.Operations) != 1 || len(d.Extensions) != 0 || d.RecoveryEpoch != in.RecoveryEpoch {
		return false
	}
	if d.Status == "draft" && (d.StateRevision != in.ExpectedStateRevision+1 || d.Revision != 1) {
		return false
	}
	op := d.Operations[0]
	return op.Sequence == 1 && op.OperationID == servicecatalog.OperationID && op.OperationType == servicecatalog.Operation && op.AdapterID == servicecatalog.AdapterID && op.TargetID == in.Definition.ServiceID && op.InputDigest == servicecatalog.Digest(in) && op.ArtifactDigest == op.InputDigest && !op.Idempotent && op.OffsiteRunSpec == nil
}
func readService(row discoveryRow, id string) (out generated.ServiceRecord, err error) {
	var raw []byte
	var digest string
	if err = row(`SELECT canonical_bytes,digest FROM service_catalog WHERE service_id=?`, id).Scan(&raw, &digest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = actionError(generated.ErrorCodeResourceNotFound)
		}
		return
	}
	if json.Unmarshal(raw, &out) != nil || generated.ValidateContractJSON(generated.SchemaIDServiceRecord, raw, generated.ContractExact) != nil || out.Definition.ServiceID != id || servicecatalog.Digest(out) != digest {
		return out, actionError(generated.ErrorCodeIntegrityFailure)
	}
	return
}
func (r *ServiceRepository) Get(ctx context.Context, id string) (out generated.ServiceRecord, err error) {
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
		if _, e := adoptionPrincipalGrant(p, row, id, "service", "read", "service.read", false); e != nil {
			return e
		}
		var e error
		out, e = readService(row, id)
		if e != nil {
			return e
		}
		return r.authorize(p, row, out.Definition, "read", "service.read")
	})
	if err != nil {
		out = generated.ServiceRecord{}
	}
	return
}
func (r *ServiceRepository) List(ctx context.Context, after string, limit int) (out generated.ServiceList, err error) {
	out = generated.ServiceList{Schema: generated.SchemaIDServiceList, SchemaVersion: "1.0.0", Services: []generated.ServiceRecord{}}
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
		if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision JOIN read_principals r ON r.principal_id=p.principal_id AND r.status='active' WHERE p.principal_id=? AND p.principal_kind=? AND p.status='active' AND g.status='active' AND g.action='read' AND g.capability='service.read' AND g.resource_kind='service'`, p.ID, string(identity.EffectivePrincipalKind(p))).Scan(&n) != nil || n == 0 {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		if e := row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&out.StateRevision, &out.RecoveryEpoch); e != nil {
			return e
		}
		rows, e := tx.query(ctx, `SELECT s.service_id FROM service_catalog s WHERE s.service_id>? AND EXISTS(SELECT 1 FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.principal_kind=? AND p.status='active' AND g.status='active' AND g.action='read' AND g.capability='service.read' AND g.resource_kind='service' AND g.resource_id=s.service_id) ORDER BY s.service_id LIMIT ?`, after, p.ID, string(identity.EffectivePrincipalKind(p)), limit+1)
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
			v, e := readService(row, id)
			if e != nil {
				return e
			}
			if e = r.authorize(p, row, v.Definition, "read", "service.read"); e != nil {
				return e
			}
			if len(out.Services) == limit {
				out.NextAfter = out.Services[limit-1].Definition.ServiceID
				break
			}
			out.Services = append(out.Services, v)
		}
		return nil
	})
	if err != nil {
		out = generated.ServiceList{}
	}
	return
}
