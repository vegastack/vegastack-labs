package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/networkconnect"
)

type NetworkEndpointRepository struct{ store *Store }

func NewNetworkEndpointRepository(s *Store) *NetworkEndpointRepository {
	return &NetworkEndpointRepository{s}
}
func endpointDeclarationID(host string) string {
	return "network-endpoint-" + hostaction.Digest(host)[7:39]
}
func ValidateNetworkEndpointDeclaration(d generated.DeclarationRevision) bool {
	present := d.NetworkEndpoint != nil || d.DeclarationType == "network.endpoint"
	for _, op := range d.Operations {
		present = present || op.AdapterID == networkconnect.AdapterID
	}
	if !present {
		return true
	}
	in := d.NetworkEndpoint
	if in == nil || networkconnect.ValidateRequest(*in) != nil || d.AuthorizationGrantBatch != nil || d.HostAliasClaim != nil || d.DeclarationType != "network.endpoint" || d.DeclarationID != endpointDeclarationID(in.Endpoint.HostID) || len(d.Operations) != 1 || len(d.Extensions) != 0 || d.RecoveryEpoch != in.RecoveryEpoch {
		return false
	}
	if d.Status == "draft" && (d.StateRevision != in.ExpectedStateRevision+1 || d.Revision != in.ExpectedDeclarationRevision+1) {
		return false
	}
	op := d.Operations[0]
	return op.Sequence == 1 && op.OperationID == "network-endpoint" && op.OperationType == networkconnect.Operation && op.AdapterID == networkconnect.AdapterID && op.TargetID == in.Endpoint.HostID && op.InputDigest == hostaction.Digest(in) && op.ArtifactDigest == op.InputDigest && !op.Idempotent && op.OffsiteRunSpec == nil
}
func currentNetworkEndpoint(row discoveryRow, host string) (generated.NetworkEndpointRequest, string, error) {
	var in generated.NetworkEndpointRequest
	var raw []byte
	var digest string
	err := row(`SELECT canonical_bytes,digest FROM network_endpoint_revisions WHERE host_id=? ORDER BY revision DESC LIMIT 1`, host).Scan(&raw, &digest)
	if err != nil {
		return in, "", err
	}
	if json.Unmarshal(raw, &in) != nil || networkconnect.ValidateRequest(in) != nil || hostaction.Digest(in) != digest {
		return in, "", actionError(generated.ErrorCodeIntegrityFailure)
	}
	return in, digest, nil
}
func networkHostBinding(row discoveryRow, e generated.NetworkEndpoint, excluded ...string) error {
	if err := requireHostUnfrozen(row, e.HostID); err != nil {
		return err
	}
	var target, digest string
	var epoch int64
	if row(`SELECT target_id,identity_digest,recovery_epoch FROM managed_hosts WHERE host_id=?`, e.HostID).Scan(&target, &digest, &epoch) != nil || target != e.TargetID || digest != e.HostIdentityDigest || epoch != e.RecoveryEpoch {
		return actionError(generated.ErrorCodePlanStale)
	}
	current, err := discoveryTarget(row, e.TargetID)
	if err != nil {
		return err
	}
	if current.Binding.Revision != e.TargetRevision || current.Binding.RecoveryEpoch != e.RecoveryEpoch || current.Binding.HostKey != e.HostKey || current.Binding.User != e.User {
		return actionError(generated.ErrorCodePlanStale)
	}
	// Exclusions are trusted deployment-profile IDs, never Labs names in core.
	for _, id := range excluded {
		var n int
		const hosts = `SELECT h.host_id FROM managed_hosts h WHERE h.host_id=?1 OR h.target_id=?1 OR h.host_id IN (SELECT owner_host_id FROM host_alias_owners WHERE alias_id=?1) OR h.identity_digest IN (SELECT owner_identity_digest FROM host_alias_owners WHERE alias_id=?1)`
		if row(`SELECT COUNT(*) FROM managed_hosts h WHERE h.host_id IN (`+hosts+`) AND (h.host_id=?2 OR h.identity_digest=?3 OR h.target_id=?4)`, id, e.HostID, e.HostIdentityDigest, e.TargetID).Scan(&n) != nil || n != 0 {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		for _, address := range []string{e.LANAddress, e.MeshAddress, e.MarkerAddress} {
			if row(`SELECT COUNT(*) FROM host_discovery_drafts d WHERE (d.target_id=?1 OR d.target_id IN (SELECT target_id FROM managed_hosts WHERE host_id IN (`+hosts+`))) AND json_extract(d.canonical_bytes,'$.target.address')=?2`, id, address).Scan(&n) != nil || n != 0 {
				return actionError(generated.ErrorCodeAuthorizationDenied)
			}
			if row(`SELECT COUNT(*) FROM network_endpoint_revisions n WHERE n.host_id IN (`+hosts+`) AND (json_extract(n.canonical_bytes,'$.endpoint.lanAddress')=?2 OR json_extract(n.canonical_bytes,'$.endpoint.meshAddress')=?2 OR json_extract(n.canonical_bytes,'$.endpoint.markerAddress')=?2)`, id, address).Scan(&n) != nil || n != 0 {
				return actionError(generated.ErrorCodeAuthorizationDenied)
			}
		}
	}

	return nil
}
func validateNetworkEndpointState(ctx context.Context, row discoveryRow, in generated.NetworkEndpointRequest, excluded ...string) error {
	if networkconnect.ValidateRequest(in) != nil {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	p, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return actionError(generated.ErrorCodeAuthenticationRequired)
	}
	if err := authorizeDeviceRow(row, p); err != nil {
		return err
	}
	if _, err := adoptionGrant(ctx, row, in.Endpoint.HostID, "host", "author", "network.endpoint.write", true); err != nil {
		return err
	}
	if err := networkHostBinding(row, in.Endpoint, excluded...); err != nil {
		return err
	}
	current, _, err := currentNetworkEndpoint(row, in.Endpoint.HostID)
	if err == sql.ErrNoRows {
		if in.ExpectedEndpointRevision != 0 {
			return actionError(generated.ErrorCodePlanStale)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if current.Endpoint.Revision != in.ExpectedEndpointRevision {
		return actionError(generated.ErrorCodePlanStale)
	}
	if in.Action == "revoke" && current.Action != "activate" {
		return actionError(generated.ErrorCodeStateConflict)
	}
	return nil
}
func (r *NetworkEndpointRepository) Stage(ctx context.Context, in generated.NetworkEndpointRequest) (generated.DeclarationRevisionRequest, error) {
	var out generated.DeclarationRevisionRequest
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	err := r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		var state, epoch int64
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || state != in.ExpectedStateRevision || epoch != in.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		return validateNetworkEndpointState(ctx, row, in, r.store.config.NetworkConnectExcludedHostIDs...)
	})
	if err != nil {
		return out, err
	}
	copy := in
	digest := hostaction.Digest(in)
	return generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", NetworkEndpoint: &copy, DeclarationID: endpointDeclarationID(in.Endpoint.HostID), DeclarationType: "network.endpoint", ExpectedRevision: in.ExpectedDeclarationRevision + 1, ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, ReasonDigest: in.ReasonDigest, Extensions: []generated.ContractExtension{}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "network-endpoint", OperationType: networkconnect.Operation, AdapterID: networkconnect.AdapterID, TargetID: in.Endpoint.HostID, InputDigest: digest, ArtifactDigest: digest, Idempotent: false}}}, nil
}
func (r *NetworkEndpointRepository) Descriptor(ctx context.Context, host string) (generated.NetworkConnectDescriptor, error) {
	var out generated.NetworkConnectDescriptor
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	err := r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		p, ok := identity.PrincipalFromContext(ctx)
		if !ok {
			return actionError(generated.ErrorCodeAuthenticationRequired)
		}
		if err := authorizeDeviceRow(row, p); err != nil {
			return err
		}
		if _, err := adoptionGrant(ctx, row, host, "host", "read", "network.connect", false); err != nil {
			return err
		}
		if row(`SELECT grant_revision FROM effective_authorization_principals WHERE principal_id=? AND status='active'`, p.ID).Scan(&out.GrantRevision) != nil {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		current, digest, err := currentNetworkEndpoint(row, host)
		if err != nil {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
		if current.Action != "activate" {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		if err = networkHostBinding(row, current.Endpoint, r.store.config.NetworkConnectExcludedHostIDs...); err != nil {
			return err
		}
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&out.StateRevision, &out.RecoveryEpoch) != nil || out.RecoveryEpoch != current.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		out.Schema = generated.SchemaIDNetworkConnectDescriptor
		out.SchemaVersion = "1.0.0"
		out.Endpoint = current.Endpoint
		out.EndpointDigest = digest
		return nil
	})
	return out, err
}
