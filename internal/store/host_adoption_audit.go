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

func (r *HostAdoptionRepository) adoptionPreparationFailure(ctx context.Context, request generated.HostAdoptionRequest, outcome *error) {
	if (*outcome == nil || (Code(*outcome) != generated.ErrorCodeAuthorizationDenied && Code(*outcome) != generated.ErrorCodeAuthenticationRequired)) || ctx.Err() != nil {
		return
	}
	if _, ok := identity.PrincipalFromContext(ctx); !ok {
		return
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		*outcome = adoptionError(generated.ErrorCodeIntegrityFailure)
		return
	}
	id := "adoption-denial-" + hex.EncodeToString(nonce[:])
	attribution, err := hostdiscovery.Attribution(ctx, id)
	if err != nil {
		*outcome = adoptionError(generated.ErrorCodeIntegrityFailure)
		return
	}
	digest := hostdiscovery.Digest([]string{hostdiscovery.Digest(request), Code(*outcome)})
	intent := discoveryIntent(attribution, "host.adoption.prepare-denied", id, hostdiscovery.Digest(id), digest)
	intent.Event.Target = audit.Target{Kind: "host-adoption-denial", ID: Code(*outcome)}
	for attempt := 0; attempt < 2; attempt++ {
		current, err := NewPlanRepository(r.store).CurrentRevision(ctx)
		if err != nil {
			break
		}
		_, err = r.store.AppendOperationalAudit(ctx, OperationalAuditRequest{Expected: current, Idempotency: intent.Idempotency, Event: intent.Event, Destinations: []audit.OutboxRequirement{}})
		if err == nil {
			return
		}
		if Code(err) != generated.ErrorCodeStateConflict {
			break
		}
	}
	*outcome = adoptionError(generated.ErrorCodeIntegrityFailure)
}
