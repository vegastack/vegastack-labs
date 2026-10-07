package hostdiscovery

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func Attribution(ctx context.Context, session string) (audit.Attribution, error) {
	p, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return audit.Attribution{}, Error(generated.ErrorCodeAuthenticationRequired)
	}
	var human *identity.Principal
	var agent *audit.AgentMetadata
	switch identity.EffectivePrincipalKind(p) {
	case identity.PrincipalHuman:
		human = &p
	case identity.PrincipalAgent:
		agent = &audit.AgentMetadata{Name: p.ID, SessionID: session}
	}
	return audit.NewAttribution(p, human, agent)
}
