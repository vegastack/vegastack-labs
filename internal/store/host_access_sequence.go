package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"time"
)

func accessDraftID(digest string) string {
	if len(digest) != 71 {
		return ""
	}
	return "host-action-" + digest[7:39]
}
func readAccessSequence(row discoveryRow, p generated.Plan) ([]HostActionDraft, error) {
	if p.HostAction != nil || p.HostAccessSequence == nil || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" {
		return nil, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	drafts := make([]HostActionDraft, len(p.Operations))
	requests := make([]generated.HostActionRequest, len(drafts))
	for i, op := range p.Operations {
		d, e := readHostActionDraft(row, accessDraftID(op.ArtifactDigest))
		if e != nil {
			return nil, e
		}
		drafts[i] = d
		requests[i] = d.Request
	}
	seq, e := debianaccess.Sequence(p.Operations, requests)
	if e != nil || hostaction.Digest(seq) != hostaction.Digest(*p.HostAccessSequence) {
		return nil, actionError(generated.ErrorCodeIntegrityFailure)
	}
	return drafts, nil
}
func actionDraftForPlan(row discoveryRow, p generated.Plan, operationID string) (HostActionDraft, generated.PlanOperation, error) {
	if p.HostAction != nil && p.HostAccessSequence == nil && len(p.Operations) == 1 && p.Operations[0].OperationID == operationID {
		d, e := readHostActionDraft(row, hostaction.DraftID(*p.HostAction))
		if e != nil {
			return d, generated.PlanOperation{}, e
		}
		if hostaction.Digest(*p.HostAction) != d.Digest {
			return d, generated.PlanOperation{}, actionError(generated.ErrorCodeIntegrityFailure)
		}
		return d, p.Operations[0], nil
	}
	drafts, e := readAccessSequence(row, p)
	if e != nil {
		return HostActionDraft{}, generated.PlanOperation{}, e
	}
	for i, op := range p.Operations {
		if op.OperationID == operationID {
			return drafts[i], op, nil
		}
	}
	return HostActionDraft{}, generated.PlanOperation{}, actionError(generated.ErrorCodePlanStale)
}
func (r *HostActionRepository) ResolveAccessSequenceStep(ctx context.Context, p generated.Plan, operationID string) (generated.HostActionRequest, error) {
	var request generated.HostActionRequest
	if r == nil || r.store == nil {
		return request, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	err := r.store.Read(ctx, func(tx ReadTx) error {
		d, op, e := actionDraftForPlan(func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) }, p, operationID)
		if e != nil {
			return e
		}
		if op.OperationType != hostaction.OperationType {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		request = d.Request
		return nil
	})
	return request, err
}
func (r *HostActionRepository) ResolveAccessLocalProbe(ctx context.Context, p generated.Plan, operationID string) (generated.HostActionRequest, generated.AccessProbeInput, error) {
	var request generated.HostActionRequest
	var probe generated.AccessProbeInput
	if r == nil || r.store == nil {
		return request, probe, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	err := r.store.Read(ctx, func(tx ReadTx) error {
		d, op, e := actionDraftForPlan(func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) }, p, operationID)
		if e != nil {
			return e
		}
		if p.HostAccessSequence == nil || op.OperationType != debianaccess.LocalProbeOperation || d.Request.ActionID != "debian.access.probe.local" || json.Unmarshal([]byte(d.Request.ActionInput), &probe) != nil {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		request = d.Request
		return nil
	})
	return request, probe, err
}

// ValidateAccessPreparation resolves every auxiliary destination against existing
// authoritative host records before rendering or connecting. It performs no I/O
// outside the control database and cannot discover an undeclared address.
func (r *HostActionRepository) ValidateAccessPreparation(ctx context.Context, requests []generated.HostActionRequest) error {
	if r == nil || r.store == nil || len(requests) == 0 {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) }
		check := func(id, identity, address string) error {
			if debianaccess.ProtectedName(id) {
				return actionError(generated.ErrorCodeAuthorizationDenied)
			}
			host, e := readManagedHost(row, id)
			if e != nil {
				return e
			}
			target, e := discoveryTarget(row, host.TargetID)
			if e != nil {
				return e
			}
			var current string
			if row(`SELECT identity_digest FROM managed_hosts WHERE host_id=?`, id).Scan(&current) != nil || current != identity || target.Binding.RecoveryEpoch != requests[0].RecoveryEpoch || address != "" && target.Binding.Address != address {
				return actionError(generated.ErrorCodePlanStale)
			}
			_, e = adoptionGrant(ctx, row, id, "host", "author", "host.action.prepare", true)
			return e
		}
		for _, request := range requests {
			if _, e := actionTarget(row, request); e != nil {
				return e
			}
			if e := check(request.HostID, request.ConsoleConfirmation.HostIdentityDigest, ""); e != nil {
				return e
			}
			if request.ActionID == "debian.access.probe.local" || request.ActionID == "debian.access.probe-source" {
				var p generated.AccessProbeInput
				if generated.ValidateContractJSON(generated.SchemaIDAccessProbeInput, []byte(request.ActionInput), generated.ContractExact) != nil || json.Unmarshal([]byte(request.ActionInput), &p) != nil {
					return actionError(generated.ErrorCodeInputInvalid)
				}
				if e := check(p.Source.HostID, p.Source.IdentityDigest, ""); e != nil {
					return e
				}
				if e := check(p.SubjectHostID, p.SubjectIdentityDigest, ""); e != nil {
					return e
				}
				subject, e := readManagedHost(row, p.SubjectHostID)
				if e != nil {
					return e
				}
				current, e := discoveryTarget(row, subject.TargetID)
				if e != nil || current.Binding.HostKey != p.SubjectHostKey {
					return actionError(generated.ErrorCodePlanStale)
				}
				for _, c := range p.Cases {
					for _, tuple := range []generated.AccessProbeTuple{c.Destination, c.Witness} {
						if e := validateAccessTuple(row, tuple, request.RecoveryEpoch, r.store.config.Clock()); e != nil {
							return e
						}
						if e := check(tuple.HostID, tuple.IdentityDigest, ""); e != nil {
							return e
						}
					}
				}
			}
		}
		return nil
	})
}

func validateAccessTuple(row discoveryRow, t generated.AccessProbeTuple, epoch int64, now time.Time) error {
	host, e := readManagedHost(row, t.HostID)
	if e != nil {
		return e
	}
	target, e := discoveryTarget(row, host.TargetID)
	if e != nil {
		return e
	}
	var identity string
	if row(`SELECT identity_digest FROM managed_hosts WHERE host_id=?`, t.HostID).Scan(&identity) != nil || identity != t.IdentityDigest || host.RecoveryEpoch != epoch || debianaccess.ProtectedName(t.HostID) {
		return actionError(generated.ErrorCodePlanStale)
	}
	if target.Binding.Address == t.Address {
		if t.OwnershipDigest != "" {
			return actionError(generated.ErrorCodeInputInvalid)
		}
		return nil
	}
	if t.OwnershipDigest == "" {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	var raw, resultRaw, receiptRaw []byte
	var status string
	if row(`SELECT c.measurement_bytes,c.result_bytes,e.canonical_bytes,c.status FROM host_control_results c JOIN execution_receipts e ON e.receipt_id=c.receipt_id AND e.result_digest=c.result_digest JOIN plan_run_steps s ON s.run_id=c.run_id AND s.step_id=c.step_id WHERE c.host_id=? AND c.host_identity_digest=? AND c.recovery_epoch=? AND c.control_id='debian.destination-ownership' AND s.status='succeeded' AND s.effect_state='verified' ORDER BY c.observed_at DESC,c.rowid DESC LIMIT 1`, t.HostID, t.IdentityDigest, epoch).Scan(&raw, &resultRaw, &receiptRaw, &status) != nil || status != "passed" {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	var m generated.AccessMeasurement
	var result generated.HostActionResult
	var receipt generated.ExecutionReceipt
	if json.Unmarshal(raw, &m) != nil || json.Unmarshal(resultRaw, &result) != nil || json.Unmarshal(receiptRaw, &receipt) != nil || hostaction.ValidateResult(result) != nil || result.ResultDigest != receipt.ResultDigest || result.ResultDigest != hostaction.ResultDigest(result) || m.MeasurementDigest != hostaction.MeasurementDigest(m) {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	included := false
	for _, v := range result.ControlMeasurements {
		if hostaction.Digest(v) == hostaction.Digest(m) {
			included = true
		}
	}
	if !included {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	for _, o := range m.DestinationOwnership {
		at, e := time.Parse(time.RFC3339Nano, o.ObservedAt)
		if e == nil && now.Sub(at) >= 0 && now.Sub(at) <= 10*time.Minute && o.HostID == t.HostID && o.IdentityDigest == t.IdentityDigest && o.Address == t.Address && hostaction.Digest(o) == t.OwnershipDigest {
			return nil
		}
	}
	return actionError(generated.ErrorCodePlanStale)
}
