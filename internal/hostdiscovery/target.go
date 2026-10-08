package hostdiscovery

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/crypto/ssh"
)

var username = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func ValidateTarget(value generated.HostDiscoveryTarget) error {
	deny := func() error { return Error(generated.ErrorCodeInputInvalid) }
	raw, err := json.Marshal(value)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDHostDiscoveryTarget, raw, generated.ContractExact) != nil {
		return deny()
	}
	address, err := netip.ParseAddr(value.Address)
	if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.Is4In6() || address.String() != value.Address || value.Port > 65535 || !username.MatchString(value.User) || value.User == "root" {
		return deny()
	}
	key, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(value.HostKey))
	if err != nil || len(rest) != 0 || len(options) != 0 || comment != "" || strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) != value.HostKey {
		return deny()
	}
	if (value.InventoryDraftID == nil) != (value.AssetID == nil) || (value.InventoryDraftID == nil && value.InventoryDraftRevision != 0) || (value.InventoryDraftID != nil && value.InventoryDraftRevision < 1) {
		return deny()
	}
	if value.CredentialMode == nil {
		if value.CredentialPublicKeyDigest != nil {
			return deny()
		}
	} else if *value.CredentialMode != "preloaded-discovery" || value.CredentialPublicKeyDigest == nil {
		return deny()
	}
	return nil
}

// ValidateConsoleConfirmation binds the administrator's attestation to the entire target.
// It is inert until the existing human acknowledgement approves its exact plan.
func ValidateConsoleConfirmation(r generated.HostDiscoveryTargetDraftRequest) error {
	raw, err := json.Marshal(r)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDHostDiscoveryTargetDraftRequest, raw, generated.ContractExact) != nil || ValidateTarget(r.Target) != nil {
		return Error(generated.ErrorCodeInputInvalid)
	}
	if r.Target.CredentialMode == nil {
		if r.ConsoleConfirmation != nil {
			return Error(generated.ErrorCodeInputInvalid)
		}
		return nil
	}
	c := r.ConsoleConfirmation
	if c == nil || c.Method != "administrator-verified-console" || c.TargetDigest != Digest(r.Target) {
		return Error(generated.ErrorCodeInputInvalid)
	}
	return nil
}
