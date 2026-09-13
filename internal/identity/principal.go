package identity

import "github.com/vegastack/vegastack-labs/internal/principal"

type PrincipalKind = principal.Kind

const (
	PrincipalHuman  = principal.Human
	PrincipalAgent  = principal.Agent
	PrincipalPolicy = principal.Policy
)

// Principal is the bounded, provider-neutral identity used by authorization.
// Kind may be empty for legacy interactive identities; those identities are
// treated as human. Agent and policy identities must always be explicit.
type Principal = principal.Principal

func EffectivePrincipalKind(principal Principal) PrincipalKind {
	if principal.Kind == "" {
		return PrincipalHuman
	}
	return principal.Kind
}

func ValidPrincipalKind(kind PrincipalKind) bool {
	switch kind {
	case PrincipalHuman, PrincipalAgent, PrincipalPolicy:
		return true
	default:
		return false
	}
}
