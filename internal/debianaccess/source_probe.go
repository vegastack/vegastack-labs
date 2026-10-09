package debianaccess

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

// PreparedProbeContext is an administrator-installed immutable context binding.
// NamespacePath comes from protected preparation, never a signed caller path.
type PreparedProbeContext struct {
	ApprovedDestinations []generated.AccessProbeTuple `json:"approvedDestinations"`
	ContextID            string                       `json:"contextId"`
	HostID               string                       `json:"hostId"`
	IdentityDigest       string                       `json:"identityDigest"`
	Kind                 string                       `json:"kind"`
	NamespacePath        string                       `json:"namespacePath"`
	NamespaceDigest      string                       `json:"namespaceDigest"`
	ProcessID            int                          `json:"processId,omitempty"`
	ContainerID          string                       `json:"containerId,omitempty"`
	ProcessStart         string                       `json:"processStart,omitempty"`
}

// The fixed preparation whitelist cannot contain a fresh receipt digest (that
// would require reinstallation and could form a self-reference). The full
// signed request still carries OwnershipDigest, validated by server authority.
func samePreparedDestination(actual, allowed generated.AccessProbeTuple) bool {
	actual.OwnershipDigest = ""
	allowed.OwnershipDigest = ""
	return hostaction.Digest(actual) == hostaction.Digest(allowed)
}
