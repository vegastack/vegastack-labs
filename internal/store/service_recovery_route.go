package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/networkingress"
)

// ValidateServiceRecoveryRoute consumes the existing independently observed,
// approved ingress journal. It never mutates routes or substitutes a DB flag.
func (r *ServiceRecoveryRepository) ValidateServiceRecoveryRoute(ctx context.Context, ingressID, bindingDigest, targetServiceID string, epoch int64) error {
	actor, e := serviceActor(ctx)
	if e != nil {
		return e
	}
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if _, e := ingressGrant(ctx, row, ingressID, "read"); e != nil {
			return e
		}
		var currentEpoch int64
		if row(`SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&currentEpoch) != nil || currentEpoch != epoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		service, e := readService(row, targetServiceID)
		if e != nil {
			return e
		}
		if e = NewServiceRepository(r.store).authorize(actor, row, service.Definition, "read", "service.read"); e != nil {
			return e
		}
		host, e := readManagedHost(row, service.Definition.HostID)
		if e != nil {
			return e
		}
		target, e := discoveryTarget(row, host.TargetID)
		if e != nil {
			return e
		}
		var port int64
		var originIdentity string
		for _, p := range r.store.config.ServiceDeploymentPolicies {
			if p.Binding.ServiceID == targetServiceID && p.Configuration != nil {
				port = p.Configuration.OriginPort
				originIdentity = p.Configuration.OriginIdentityDigest
			}
		}
		if port < 1 || originIdentity == "" {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
		var raw []byte
		var scope, status, at string
		if row(`SELECT d.request_bytes,w.scope_digest,o.status,o.observed_at FROM ingress_ownership w JOIN ingress_drafts d ON d.draft_id=w.draft_id JOIN ingress_observations o ON o.draft_id=w.draft_id AND o.run_id=w.run_id AND o.profile_id=w.profile_id AND o.recovery_epoch=w.recovery_epoch JOIN plan_runs r ON r.run_id=w.run_id WHERE w.profile_id=? AND w.recovery_epoch=? AND r.status='succeeded' AND o.rowid=(SELECT MAX(x.rowid) FROM ingress_observations x WHERE x.profile_id=w.profile_id AND x.recovery_epoch=w.recovery_epoch) ORDER BY w.revision DESC LIMIT 1`, ingressID, epoch).Scan(&raw, &scope, &status, &at) != nil || status != "observed" || scope != bindingDigest {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
		var q generated.IngressDraftRequest
		when, e := time.Parse(time.RFC3339, at)
		now := r.store.config.Clock().UTC()
		if e != nil || when.After(now.Add(time.Second)) || now.Sub(when) > 5*time.Minute || json.Unmarshal(raw, &q) != nil || networkingress.Validate(q.Change) != nil || networkingress.OwnershipDigest(q.Change) != scope || q.RecoveryEpoch != epoch || q.Change.OriginIdentityDigest != originIdentity {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
		origin, e := url.Parse(q.Change.OriginService)
		if e != nil || origin.Hostname() != target.Binding.Address || origin.Port() != strconv.FormatInt(port, 10) {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
		return nil
	})
}

// HasServiceRecoveryTargetRoute treats any applied target route as an
// irreversible writer boundary, even when a later plan changes the route back.
func (r *ServiceRecoveryRepository) HasServiceRecoveryTargetRoute(ctx context.Context, ingressID, bindingDigest, targetServiceID string, epoch int64) (found bool, err error) {
	actor, e := serviceActor(ctx)
	if e != nil {
		return false, e
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if _, e := ingressGrant(ctx, row, ingressID, "read"); e != nil {
			return e
		}
		service, e := readService(row, targetServiceID)
		if e != nil {
			return e
		}
		if e = NewServiceRepository(r.store).authorize(actor, row, service.Definition, "read", "service.read"); e != nil {
			return e
		}
		host, e := readManagedHost(row, service.Definition.HostID)
		if e != nil {
			return e
		}
		target, e := discoveryTarget(row, host.TargetID)
		if e != nil {
			return e
		}
		rows, e := tx.query(ctx, `SELECT d.request_bytes FROM ingress_ownership w JOIN ingress_drafts d ON d.draft_id=w.draft_id JOIN ingress_observations o ON o.draft_id=w.draft_id AND o.run_id=w.run_id AND o.profile_id=w.profile_id AND o.recovery_epoch=w.recovery_epoch WHERE w.profile_id=? AND w.scope_digest=? AND w.recovery_epoch=? AND o.status='observed'`, ingressID, bindingDigest, epoch)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if rows.Scan(&raw) != nil {
				return actionError(generated.ErrorCodeIntegrityFailure)
			}
			var q generated.IngressDraftRequest
			if json.Unmarshal(raw, &q) != nil {
				return actionError(generated.ErrorCodeIntegrityFailure)
			}
			u, e := url.Parse(q.Change.OriginService)
			if e != nil {
				return actionError(generated.ErrorCodeIntegrityFailure)
			}
			if u.Hostname() == target.Binding.Address {
				found = true
			}
		}
		return rows.Err()
	})
	return
}
