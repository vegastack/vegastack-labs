package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func (r *HostDiscoveryRepository) discoveryFailureAudit(ctx context.Context, operation, target string, outcome *error) {
	if *outcome == nil || ctx.Err() != nil {
		return
	}
	if _, ok := identity.PrincipalFromContext(ctx); !ok {
		return
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		*outcome = discoveryError(generated.ErrorCodeIntegrityFailure)
		return
	}
	id := "discovery-failure-" + hex.EncodeToString(nonce[:])
	attribution, err := hostdiscovery.Attribution(ctx, id)
	if err != nil {
		*outcome = discoveryError(generated.ErrorCodeIntegrityFailure)
		return
	}
	digest := hostdiscovery.Digest([]string{operation, target, Code(*outcome)})
	intent := discoveryIntent(attribution, "host.discovery.failed", id, hostdiscovery.Digest(id), digest)
	for attempt := 0; attempt < 2; attempt++ {
		health, err := r.store.Health(ctx)
		if err != nil {
			break
		}
		_, err = r.store.AppendOperationalAudit(ctx, OperationalAuditRequest{Expected: health.Revision, Idempotency: intent.Idempotency, Event: intent.Event, Destinations: []audit.OutboxRequirement{}})
		if err == nil {
			return
		}
		if Code(err) != generated.ErrorCodeStateConflict {
			break
		}
	}
	*outcome = discoveryError(generated.ErrorCodeIntegrityFailure)
}
