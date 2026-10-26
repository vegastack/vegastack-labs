// Package networkmesh defines the bounded owned Mesh workflow, without provider authority.
package networkmesh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"net/netip"
	"regexp"
	"slices"
)

const AdapterID = "cloudflare.mesh"
const PurposeRead = "mesh.observe"
const PurposeWrite = "mesh.mutate"
const Extension = "x-cloudflare-mesh-change"
const OperationID = "mesh-change"

var id = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)
var account = regexp.MustCompile(`^[a-f0-9]{32}$`)
var resource = regexp.MustCompile(`^[a-f0-9-]{36}$`)
var digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func Error(code string) error { return failure.New(code, "network-mesh", false) }
func Digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
func ValidRoute(s string) bool {
	p, e := netip.ParsePrefix(s)
	return e == nil && p.String() == s && p == p.Masked() && p.Bits() > 0 && !p.Addr().IsMulticast() && !p.Addr().IsUnspecified()
}
func ScopeDigest(c generated.MeshChange) string {
	x := slices.Clone(c.AffectedIdentityDigests)
	slices.Sort(x)
	return Digest([]any{c.AccountID, c.ResourceKind, c.ResourceID, c.Mode, x})
}
func OwnershipDigest(c generated.MeshChange) string {
	x := slices.Clone(c.AffectedIdentityDigests)
	slices.Sort(x)
	return Digest([]any{c.AccountID, c.ResourceKind, c.ResourceID, x})
}
func ResourceKey(c generated.MeshChange) string {
	return Digest([]string{c.AccountID, c.ResourceKind, c.ResourceID})
}
func Validate(c generated.MeshChange) error {
	bad := func() error { return Error(generated.ErrorCodeInputInvalid) }
	if c.Mode != "foundation" && c.Mode != "qualified" {
		return bad()
	}
	if !id.MatchString(c.ProfileID) || !account.MatchString(c.AccountID) || !resource.MatchString(c.ResourceID) || !id.MatchString(c.OwnerID) || !id.MatchString(c.DeviceID) || !digest.MatchString(c.BeforeDigest) || !ValidRoute(c.MeshCIDR) || len(c.AffectedIdentityDigests) == 0 || len(c.AffectedIdentityDigests) > 128 || c.ObservationReferenceID == c.MutationReferenceID || !id.MatchString(c.ObservationReferenceID) || !id.MatchString(c.MutationReferenceID) {
		return bad()
	}
	seen := map[string]bool{}
	for _, d := range c.AffectedIdentityDigests {
		if !digest.MatchString(d) || seen[d] {
			return bad()
		}
		seen[d] = true
	}
	if c.ExpectedOwnershipRevision < 0 || len(c.Routes) > 128 {
		return bad()
	}
	for _, r := range c.Routes {
		if !ValidRoute(r.Address) {
			return bad()
		}
	}
	switch c.ResourceKind {
	case "profile-include", "profile-exclude":
		if c.Action != "import" && c.Action != "profile-routing-update" {
			return bad()
		}
	case "gateway-rule":
		if c.Action != "import" && c.Action != "gateway-rule-update" {
			return bad()
		}
		if c.RuleName == "" || len(c.RuleName) > 128 || c.Traffic == "" || len(c.Traffic) > 2048 || len(c.RuleIdentity) > 2048 || c.RuleAction != "allow" && c.RuleAction != "block" || c.Precedence < 0 {
			return bad()
		}
	case "registration":
		if c.Action != "import" && c.Action != "registration-delete" || !resource.MatchString(c.PhysicalDeviceID) || !resource.MatchString(c.ProviderUserID) {
			return bad()
		}
	default:
		return bad()
	}
	if c.Action == "import" && c.ExpectedOwnershipRevision != 0 || c.Action != "import" && c.ExpectedOwnershipRevision < 1 {
		return bad()
	}
	return nil
}

type Staged struct {
	ID, Digest, ActorID, ActorMethod, ActorDevice string
	Request                                       generated.MeshDraftRequest
	Bindings                                      []credentialref.StepBinding
}
type Snapshot struct {
	Digest, Reason                                                string
	Present                                                       bool
	Routes                                                        []generated.MeshRoute
	RegistrationID, PhysicalDeviceID, ProviderUserID, VirtualIPv4 string
	RuleName, RuleAction, Traffic, Identity                       string
	Precedence                                                    int64
	Enabled                                                       bool
}

// Authority is implemented by server-owned storage/composition, never request booleans.
type Authority interface {
	Resolve(context.Context, adapter.Operation, adapter.ExactExecutionBinding) (Staged, error)
	BorrowRead(context.Context, Staged) (*credentialref.Value, error)
	Record(context.Context, Staged, adapter.ExactExecutionBinding, Snapshot, string) error
}
