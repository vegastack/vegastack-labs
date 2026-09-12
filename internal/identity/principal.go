package identity

import "regexp"

type PrincipalKind string

const (
	PrincipalHuman  PrincipalKind = "human"
	PrincipalAgent  PrincipalKind = "agent"
	PrincipalPolicy PrincipalKind = "policy"
)

var principalIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)

// Principal is the bounded, provider-neutral identity used by authorization.
// Kind may be empty for legacy interactive identities; those identities are
// treated as human. Agent and policy identities must always be explicit.
type Principal struct {
	ID     string
	Method string
	Kind   PrincipalKind
}

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
