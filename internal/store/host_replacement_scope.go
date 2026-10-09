package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"slices"
)

// Resolve only existing declared ownership. Unknown target operations cannot be
// reclassified as stateless merely because the caller supplies no payload IDs.
func (r *HostReplacementRepository) validateReplacementOwnedScope(ctx context.Context, tx ReadTx, q generated.HostReplacementRequest) error {
	rows, err := tx.query(ctx, `SELECT d.canonical_bytes,d.reason_digest FROM declaration_revisions d WHERE d.status!='superseded' AND EXISTS (SELECT 1 FROM json_each(d.canonical_bytes,'$.operations') o WHERE json_extract(o.value,'$.targetId')=?) AND (d.declaration_type='host.volume' OR EXISTS (SELECT 1 FROM immutable_plans p JOIN plan_run_steps s ON s.run_id IN (SELECT run_id FROM plan_runs WHERE plan_id=p.plan_id) WHERE p.declaration_id=d.declaration_id AND s.target_id=? AND s.effect_state IN ('intent-recorded','receipt-recorded','effect-unknown','verified'))) AND NOT EXISTS(SELECT 1 FROM declaration_revisions n WHERE n.declaration_id=d.declaration_id AND n.declaration_revision>d.declaration_revision) ORDER BY d.declaration_id LIMIT 257`, q.OldHostID, q.OldHostID)
	if err != nil {
		return err
	}
	resources := []string{}
	declarations := map[string]bool{}
	volumeDeclarations := map[string]generated.DeclarationRevision{}
	count := 0
	for rows.Next() {
		count++
		var raw []byte
		var reason string
		var d generated.DeclarationRevision
		if rows.Scan(&raw, &reason) != nil || !decodeStoredDeclaration(raw, reason, &d) {
			rows.Close()
			return replacementError(generated.ErrorCodeIntegrityFailure)
		}
		subject := false
		for _, op := range d.Operations {
			if op.TargetID != q.OldHostID {
				continue
			}
			if op.AdapterID == "core.gate" && (op.OperationType == "gate.evidence.apply" || op.OperationType == "gate.evidence.revoke" || op.OperationType == "gate.evidence.supersede") {
				continue
			}
			subject = true
			if d.DeclarationType == "host.volume" && op.AdapterID == "core.host-action" && op.OperationType == "host.volume" {
				volumeDeclarations[d.DeclarationID] = d
				continue
			}
			if op.OperationType != "host.action.execute" && op.OperationType != debianaccess.LocalProbeOperation {
				rows.Close()
				return replacementError(generated.ErrorCodePrerequisiteBlocked)
			}
		}
		if subject {
			resources = append(resources, d.DeclarationID)
			declarations[d.DeclarationID] = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if count > 256 || len(resources) > 32 || !slices.Equal(resources, q.ResourceIDs) {
		return replacementError(generated.ErrorCodePrerequisiteBlocked)
	}
	rows, err = tx.query(ctx, `SELECT DISTINCT p.canonical_bytes FROM immutable_plans p JOIN plan_runs r ON r.plan_id=p.plan_id AND r.plan_digest=p.plan_digest JOIN plan_run_steps s ON s.run_id=r.run_id WHERE s.target_id=? AND s.effect_state IN ('intent-recorded','receipt-recorded','effect-unknown','verified') ORDER BY p.state_revision DESC LIMIT 257`, q.OldHostID)
	if err != nil {
		return err
	}
	volumes := map[string]bool{}
	seen := map[string]bool{}
	count = 0
	for rows.Next() {
		count++
		var raw []byte
		var p generated.Plan
		if rows.Scan(&raw) != nil || json.Unmarshal(raw, &p) != nil {
			rows.Close()
			return replacementError(generated.ErrorCodeIntegrityFailure)
		}
		if _, volume := volumeDeclarations[p.DeclarationID]; volume {
			continue
		}
		if !declarations[p.DeclarationID] || seen[p.DeclarationID] {
			continue
		}
		seen[p.DeclarationID] = true
		if p.HostAccessSequence != nil {
			continue
		}
		if p.HostAction == nil {
			rows.Close()
			return replacementError(generated.ErrorCodePrerequisiteBlocked)
		}
		action := p.HostAction.ActionID
		switch {
		case linuxrole.IsAction(action):
		case debianbaseline.IsAction(action):
			in, e := debianbaseline.DecodeInput([]byte(p.HostAction.ActionInput))
			if e != nil {
				rows.Close()
				return e
			}
			for _, v := range in.Volumes {
				if v.HostID == q.OldHostID {
					volumes[v.VolumeID] = true
				}
			}
		case action == "debian.access.collect" || action == "debian.access.probe-source" || action == "debian.access.probe.local":
		default:
			rows.Close()
			return replacementError(generated.ErrorCodePrerequisiteBlocked)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if count > 256 {
		return replacementError(generated.ErrorCodePrerequisiteBlocked)
	}
	if len(volumeDeclarations) > 0 {
		row := func(query string, args ...any) *sql.Row { return tx.queryRow(ctx, query, args...) }
		snapshot := HostAdmissionSnapshot{Host: generated.ManagedHost{HostID: q.OldHostID}, IdentityDigest: q.OldIdentityDigest, Revision: RevisionToken{RecoveryEpoch: q.RecoveryEpoch}}
		if err := r.gates.admissionMeasurements(ctx, tx, &snapshot); err != nil {
			return err
		}
		for id, d := range volumeDeclarations {
			found := false
			for _, measured := range snapshot.Measurements {
				if measured.Measurement.Volume == nil || measured.Measurement.Status != "passed" {
					continue
				}
				b := measured.Measurement.Volume.Binding
				if b.DeclarationID != id || b.DeclarationRevision != d.Revision || b.HostID != q.OldHostID {
					continue
				}
				if err := validateCurrentVolumeDeclaration(row, b); err != nil {
					return err
				}
				for _, op := range d.Operations {
					if op.TargetID == q.OldHostID && (op.InputDigest != hostaction.Digest(b) || op.ArtifactDigest != hostaction.Digest(b)) {
						return replacementError(generated.ErrorCodePlanStale)
					}
				}
				volumes[b.VolumeID] = true
				found = true
			}
			if !found {
				return replacementError(generated.ErrorCodePrerequisiteBlocked)
			}
		}
	}
	ids := []string{}
	for id := range volumes {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, q.VolumeIDs) || len(q.PayloadIDs) != 0 {
		return replacementError(generated.ErrorCodePrerequisiteBlocked)
	}
	return nil
}
