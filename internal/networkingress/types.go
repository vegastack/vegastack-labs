// Package networkingress defines narrow owned ingress declarations and honest partial rotation state.
package networkingress

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
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

const AdapterID = "cloudflare.ingress"
const PurposeRead = "ingress.observe"
const PurposeWrite = "ingress.mutate"
const PurposeReplacement = "ingress.tunnel-secret"
const Extension = "x-cloudflare-ingress-change"
const OperationID = "ingress-change"

var token = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)
var account = regexp.MustCompile(`^[a-f0-9]{32}$`)
var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var hostname = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)

func Error(code string) error { return failure.New(code, "network-ingress", false) }
func Digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
func ResourceKey(c generated.IngressChange) string {
	switch c.ResourceKind {
	case "access-policy":
		return Digest([]string{c.AccountID, "access-policy", c.AccessAppID, c.AccessPolicyID})
	case "dns-record":
		return Digest([]string{c.ZoneID, "dns-record", c.DNSRecordID})
	default:
		// Configuration, token rotation and connector cleanup share the tunnel owner.
		return Digest([]string{c.AccountID, "tunnel", c.TunnelID})
	}
}
func OwnershipDigest(c generated.IngressChange) string {
	x := slices.Clone(c.Connectors)
	slices.SortFunc(x, func(a, b generated.IngressConnectorTarget) int { return strings.Compare(a.ConnectorID, b.ConnectorID) })
	return Digest([]any{ResourceKey(c), c.AccountID, c.ZoneID, c.TunnelID, c.Hostname, c.AccessAppID, c.AccessPolicyID, c.DNSRecordID, x})
}
func ScopeDigest(c generated.IngressChange) string {
	return Digest([]any{OwnershipDigest(c), c.OriginService, c.OriginServerName, c.OriginIdentityDigest})
}
func Validate(c generated.IngressChange) error {
	bad := func() error { return Error(generated.ErrorCodeInputInvalid) }
	if !token.MatchString(c.ProfileID) || !token.MatchString(c.OwnerID) || !token.MatchString(c.DeviceID) || !account.MatchString(c.AccountID) || !account.MatchString(c.ZoneID) || !uuid.MatchString(c.TunnelID) || !digest.MatchString(c.BeforeDigest) || !hostname.MatchString(c.Hostname) || len(c.Hostname) > 253 || strings.Contains(c.Hostname, "*") || !uuid.MatchString(c.AccessAppID) || !uuid.MatchString(c.AccessPolicyID) || !account.MatchString(c.DNSRecordID) || len(c.Connectors) == 0 || len(c.Connectors) > 16 {
		return bad()
	}
	u, e := url.Parse(c.OriginService)
	if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return bad()
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if e != nil || !ip.IsPrivate() || !digest.MatchString(c.OriginIdentityDigest) || !hostname.MatchString(c.OriginServerName) {
		return bad()
	}
	seen := map[string]bool{}
	hosts := map[string]bool{}
	for _, x := range c.Connectors {
		if !uuid.MatchString(x.ConnectorID) || !token.MatchString(x.HostID) || x.HostID == "vsk-node-04" || x.HostID == "vsk-node-05" || !digest.MatchString(x.IdentityDigest) || seen[x.ConnectorID] || hosts[x.HostID] {
			return bad()
		}
		seen[x.ConnectorID] = true
		hosts[x.HostID] = true
	}
	for _, r := range []string{c.ObservationReferenceID, c.MutationReferenceID, c.ReplacementReferenceID} {
		if !token.MatchString(r) {
			return bad()
		}
	}
	if c.ObservationReferenceID == c.MutationReferenceID || c.ReplacementReferenceID == c.ObservationReferenceID || c.ReplacementReferenceID == c.MutationReferenceID {
		return bad()
	}
	switch c.ResourceKind {
	case "tunnel-configuration":
		if c.ResourceID != c.TunnelID || c.Action != "import" && c.Action != "tunnel-config-update" {
			return bad()
		}
	case "access-policy":
		if c.ResourceID != c.AccessPolicyID || c.Action != "import" && c.Action != "access-policy-update" || len(c.AllowedGroupIDs) == 0 || len(c.AllowedGroupIDs) > 128 || c.PolicyName == "" || c.Precedence < 0 {
			return bad()
		}
		for _, s := range c.AllowedGroupIDs {
			if !uuid.MatchString(s) {
				return bad()
			}
		}
	case "dns-record":
		if c.ResourceID != c.DNSRecordID || c.Action != "import" && c.Action != "dns-record-update" {
			return bad()
		}
	case "connector":
		if c.ResourceID != c.ConnectorID || !seen[c.ConnectorID] || c.Action != "import" && c.Action != "connector-disconnect" {
			return bad()
		}
	case "tunnel-token":
		if c.ResourceID != c.TunnelID || c.Action != "import" && c.Action != "token-rotate" {
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
	Request                                       generated.IngressDraftRequest
	Bindings                                      []credentialref.StepBinding
}
type Connection struct {
	ConnectorID, ConnectionID string
	OpenedAt                  time.Time
}
type Snapshot struct {
	StateDigest                               string
	Config                                    map[string]json.RawMessage `json:"-"`
	Policy                                    map[string]json.RawMessage `json:"-"`
	Digest, Reason                            string
	Present                                   bool
	OriginTLSVerified                         bool
	Hostname, OriginService, OriginServerName string
	PolicyName                                string
	AllowedGroupIDs                           []string
	Precedence                                int64
	DNSName, DNSContent                       string
	DNSProxied                                bool
	Connections                               []Connection
}
type Authority interface {
	Resolve(context.Context, adapter.Operation, adapter.ExactExecutionBinding) (Staged, error)
	BorrowRead(context.Context, Staged) (*credentialref.Value, error)
	Record(context.Context, Staged, adapter.ExactExecutionBinding, Snapshot, string) error
}
