// Package authorization defines provider-neutral, resource-scoped read grants.
package authorization

import (
	"context"
	"fmt"
	"regexp"

	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/inventory"
)

var tokenPattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)

type ReadTarget struct {
	Capability   string
	ResourceKind string
	ResourceID   string
}

type ReadScope struct {
	PrincipalID   string
	Capability    string
	ResourceKind  string
	GrantRevision int64
	ScopeDigest   string
}

type ReadAuthorizer interface {
	AuthorizeRead(context.Context, identity.Principal, ReadTarget) (ReadScope, error)
}

func ResourceID(ref inventory.DraftRef) string {
	if ref.Revision <= 0 || !tokenPattern.MatchString(string(ref.ID)) {
		return ""
	}
	value := fmt.Sprintf("%s:%d", ref.ID, ref.Revision)
	if len(value) > 128 {
		return ""
	}
	return value
}

func ValidTarget(target ReadTarget) bool {
	return tokenPattern.MatchString(target.Capability) && tokenPattern.MatchString(target.ResourceKind) && (target.ResourceID == "" || tokenPattern.MatchString(target.ResourceID))
}
