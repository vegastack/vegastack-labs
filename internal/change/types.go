// Package change owns provider-neutral inert declaration revisions.
package change

import "github.com/vegastack/vegastack-labs/internal/generated"

type AuthorScope struct {
	PrincipalID     string
	PrincipalMethod string
	AgentName       string
	AgentSessionID  string
}

type Result struct {
	Document generated.DeclarationRevision
	Changed  bool
	Created  bool
}
