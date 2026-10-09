// Package debianaccess contains finite Debian access actions and their input validation.
package debianaccess

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"golang.org/x/crypto/ssh"
)

const MaximumInput = 32768
const ActionVersion = "1.0.0"

var accountName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
var interfaceName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.:-]{0,14}$`)
var errInput = errors.New("invalid Debian access input")

func DecodeInput(raw []byte) (generated.DebianAccessInput, error) {
	var in generated.DebianAccessInput
	if len(raw) == 0 || len(raw) > MaximumInput || strictjson.Scan(context.Background(), raw, strictjson.Limits{MaxDepth: 16}) != nil || generated.ValidateContractJSON(generated.SchemaIDDebianAccessInput, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &in) != nil {
		return in, errInput
	}
	return in, ValidateInput(in)
}
func ValidateInput(in generated.DebianAccessInput) error {
	if err := ValidateDesiredInput(in); err != nil {
		return err
	}
	if in.RenderedAccessDigest != hostaction.Digest(in.RenderedAccess) || in.RenderedAccess.ProfileLockDigest != in.ProfileLockDigest || in.RenderedAccess.RendererDigest != in.ProfileLock.RoleDigest {
		return errInput
	}
	r := in.RenderedAccess
	if hostaction.Digest(r.Accounts) != hostaction.Digest(in.Accounts) || hostaction.Digest(r.SSHUsers) != hostaction.Digest(in.SSHUsers) || hostaction.Digest(r.SSHSourcePrefixes) != hostaction.Digest(in.SSHSourcePrefixes) || hostaction.Digest(r.RecoverySourcePrefixes) != hostaction.Digest(in.RecoverySourcePrefixes) || hostaction.Digest(r.PrivilegedServiceKeys) != hostaction.Digest(in.PrivilegedServiceKeys) || hostaction.Digest(r.Interfaces) != hostaction.Digest(in.Interfaces) || hostaction.Digest(r.HostFlows) != hostaction.Digest(in.HostFlows) || hostaction.Digest(r.ContainerFlows) != hostaction.Digest(in.ContainerFlows) {
		return errInput
	}
	return ValidateEnvelopeCapacity(in)
}

// ValidateDesiredInput checks finite desired state before the fixed renderer runs.
// The final signed input must additionally pass ValidateInput.
func ValidateDesiredInput(in generated.DebianAccessInput) error {
	raw, marshalErr := json.Marshal(in)
	if marshalErr != nil {
		return errInput
	}
	for _, marker := range []string{"{{", "{%", "{#", `\n`, `\r`, `\t`, `\u000`} {
		if strings.Contains(string(raw), marker) {
			return errInput
		}
	}
	if in.ActionVersion != ActionVersion || in.AutomationUID <= 0 || in.AutomationUID > 4294967295 || ProtectedName(in.HostID) || in.HostID == "" || in.HostIdentityDigest == "" || in.ProfileID == "" || in.ProfileLockDigest != hostaction.Digest(in.ProfileLock) || in.ProfileLock.OSFamily != "debian" || in.ProfileLock.OSVersion != "13.6" || in.ProfileLock.Architecture != "amd64" || in.ProfileLock.Backend != "iptables-nft" || len(in.ProfileLock.Packages) == 0 {
		return errInput
	}
	packages := map[string]bool{}
	for _, p := range in.ProfileLock.Packages {
		if packages[p.Name] || p.Name == "" || p.Version == "" || strings.ContainsAny(p.Version, "\n\r\x00") {
			return errInput
		}
		packages[p.Name] = true
	}
	if len(in.Accounts) == 0 || len(in.Accounts) > 32 || len(in.SSHUsers) == 0 || len(in.SSHUsers) > 32 || len(in.Interfaces) == 0 || len(in.Interfaces) > 16 || len(in.PrivilegedServiceKeys) > 8 {
		return errInput
	}
	names := map[string]generated.AccessAccount{}
	uids := map[int64]bool{}
	homes := map[string]bool{}
	automation := 0
	keyRoles := map[string]string{}
	for _, a := range in.Accounts {
		if !accountName.MatchString(a.Name) || a.Name == "root" || ProtectedName(a.Name) || a.UID <= 0 || a.GID <= 0 || a.UID > 4294967295 || a.GID > 4294967295 || uids[a.UID] || homes[a.Home] || names[a.Name].Name != "" || path.Clean(a.Home) != a.Home || strings.ContainsAny(a.Home, "\n\r\x00${} ") {
			return errInput
		}
		if a.Role != "human" && a.Role != "automation" && a.Role != "service" {
			return errInput
		}
		if a.Home != "/home/"+a.Name && !(a.Role == "service" && a.Home == "/var/lib/"+a.Name) {
			return errInput
		}
		if len(a.PublicKeys) == 0 || len(a.PublicKeys) > 8 || len(a.PublicKeys) != len(a.PublicKeyDigests) {
			return errInput
		}
		for i, key := range a.PublicKeys {
			parsed, _, _, _, keyErr := ssh.ParseAuthorizedKey([]byte(key))
			if keyErr != nil {
				return errInput
			}
			fingerprint := ssh.FingerprintSHA256(parsed)
			if old, exists := keyRoles[fingerprint]; exists && old != a.Role {
				return errInput
			}
			keyRoles[fingerprint] = a.Role
			if !validPublicKey(key) || hostaction.BytesDigest([]byte(key)) != a.PublicKeyDigests[i] {
				return errInput
			}
			for j := 0; j < i; j++ {
				if a.PublicKeys[j] == key {
					return errInput
				}
			}
		}
		names[a.Name] = a
		uids[a.UID] = true
		homes[a.Home] = true
		if a.Role == "automation" {
			automation++
			if a.UID != in.AutomationUID {
				return errInput
			}
		}
	}
	if automation != 1 {
		return errInput
	}
	seen := map[string]bool{}
	for _, name := range in.SSHUsers {
		if names[name].Name == "" || seen[name] || name == "root" {
			return errInput
		}
		seen[name] = true
	}
	if err := validatePrefixes(in.SSHSourcePrefixes); err != nil {
		return err
	}
	if err := validatePrefixes(in.RecoverySourcePrefixes); err != nil {
		return err
	}
	if len(in.RecoverySourcePrefixes) == 0 || len(in.SSHSourcePrefixes) == 0 {
		return errInput
	}
	for _, p := range in.RecoverySourcePrefixes {
		if !prefixCovered(p, in.SSHSourcePrefixes) {
			return errInput
		}
	}
	for _, key := range in.PrivilegedServiceKeys {
		parsed, _, _, _, keyErr := ssh.ParseAuthorizedKey([]byte(key.PublicKey))
		if keyErr != nil {
			return errInput
		}
		fingerprint := ssh.FingerprintSHA256(parsed)
		if _, exists := keyRoles[fingerprint]; exists {
			return errInput
		}
		keyRoles[fingerprint] = "privileged-service"
		if !accountName.MatchString(key.ServiceID) || !validPublicKey(key.PublicKey) || hostaction.BytesDigest([]byte(key.PublicKey)) != key.PublicKeyDigest || len(key.SourcePrefixes) == 0 || validatePrefixes(key.SourcePrefixes) != nil {
			return errInput
		}
	}
	interfaces := map[string]generated.AccessInterface{}
	indices := map[int64]bool{}
	ipv6 := false
	for _, i := range in.Interfaces {
		if !interfaceName.MatchString(i.Name) || i.Index <= 0 || indices[i.Index] || interfaces[i.Name].Name != "" || len(i.Addresses) == 0 {
			return errInput
		}
		indices[i.Index] = true
		interfaces[i.Name] = i
		for _, s := range i.Addresses {
			a, e := netip.ParseAddr(s)
			if e != nil || a.String() != s || a.IsUnspecified() || a.IsMulticast() || a.Is6() && !i.IPv6Enabled {
				return errInput
			}
			ipv6 = ipv6 || a.Is6()
		}
	}
	for _, prefix := range append(append([]string{}, in.SSHSourcePrefixes...), in.RecoverySourcePrefixes...) {
		p, _ := netip.ParsePrefix(prefix)
		if p.Addr().Is6() && !ipv6 {
			return errInput
		}
	}
	if len(in.HostFlows) > 64 || len(in.ContainerFlows) > 64 {
		return errInput
	}
	for _, flows := range [][]generated.AccessFlow{in.HostFlows, in.ContainerFlows} {
		keys := map[string]bool{}
		for _, f := range flows {
			i, ok := interfaces[f.Interface]
			if !ok || f.Port < 1 || f.Port > 65535 || (f.Protocol != "tcp" && f.Protocol != "udp") || validatePrefixes([]string{f.SourcePrefix, f.DestinationPrefix}) != nil {
				return errInput
			}
			src, _ := netip.ParsePrefix(f.SourcePrefix)
			dst, _ := netip.ParsePrefix(f.DestinationPrefix)
			if src.Addr().Is6() != dst.Addr().Is6() || src.Addr().Is6() && !i.IPv6Enabled {
				return errInput
			}
			k := hostaction.Digest(f)
			if keys[k] {
				return errInput
			}
			keys[k] = true
		}
	}
	s := in.RollbackSpecification
	if s.HostID != in.HostID || s.HostIdentityDigest != in.HostIdentityDigest || s.ProfileLockDigest != in.ProfileLockDigest || s.DeadlineSeconds != 600 || len(s.OwnedState) == 0 || hostaction.Digest(s.RecoverySourcePrefixes) != hostaction.Digest(in.RecoverySourcePrefixes) || in.RollbackDigest != hostaction.Digest(s) {
		return errInput
	}
	owned := map[string]bool{}
	for _, v := range s.OwnedState {
		if !OwnedResource(v.ResourceID) || owned[v.ResourceID] || v.BeforeDigest == "" || v.AfterDigest == "" {
			return errInput
		}
		owned[v.ResourceID] = true
	}
	return nil
}
func OwnedResource(id string) bool {
	if id == "service-root-keys" || id == "ssh-config" || id == "host-rules-v4" || id == "host-rules-v6" || id == "container-rules-v4" || id == "container-rules-v6" {
		return true
	}
	if strings.HasPrefix(id, "authorized-keys:") {
		return accountName.MatchString(strings.TrimPrefix(id, "authorized-keys:"))
	}
	return false
}
func ProtectedName(s string) bool {
	s = strings.ToLower(strings.NewReplacer("-", "", "_", "", ".", "").Replace(s))
	return s == "vsknode04" || s == "vsknode05" || s == "node04" || s == "node05" || s == "node4" || s == "node5"
}
func validPublicKey(s string) bool {
	if strings.ContainsAny(s, "\n\r\x00") {
		return false
	}
	_, _, options, rest, e := ssh.ParseAuthorizedKey([]byte(s))
	return e == nil && len(options) == 0 && len(rest) == 0
}
func validatePrefixes(values []string) error {
	if len(values) > 64 {
		return errInput
	}
	seen := map[string]bool{}
	for _, s := range values {
		p, e := netip.ParsePrefix(s)
		if e != nil || p.Masked().String() != s || p.Bits() == 0 || p.Addr().IsMulticast() || seen[s] {
			return errInput
		}
		seen[s] = true
	}
	return nil
}
func prefixCovered(value string, parents []string) bool {
	p, e := netip.ParsePrefix(value)
	if e != nil {
		return false
	}
	for _, s := range parents {
		q, e := netip.ParsePrefix(s)
		if e == nil && q.Addr().BitLen() == p.Addr().BitLen() && q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// ValidateEnvelopeCapacity reserves the actual escaped signed-envelope overhead
// before acknowledgement; no future execution identifier is allocated here.
func ValidateEnvelopeCapacity(in generated.DebianAccessInput) error {
	raw, e := json.Marshal(in)
	if e != nil || len(raw) > MaximumInput {
		return errInput
	}
	id := "a" + strings.Repeat("x", 127)
	d := "sha256:" + strings.Repeat("a", 64)
	b := generated.HostActionBundle{Schema: generated.SchemaIDHostActionBundle, SchemaVersion: "1.0.0", ActionID: "debian.access.apply", ActionVersion: ActionVersion, ActionInput: string(raw), ActionInputDigest: hostaction.BytesDigest(raw), BundleID: id, PlanID: id, RunID: id, StepID: id, LeaseID: id, HostID: id, DeclarationID: id, AutomationPrincipalID: id, CredentialReferenceID: id, CredentialMaterialVersion: id, PlanDigest: d, HostIdentityDigest: d, ConsoleConfirmationDigest: d, DeclarationRevision: 9223372036854775807, StateRevision: 9223372036854775807, RecoveryEpoch: 9223372036854775807, CallerUID: 4294967295, IssuedAt: "2026-10-09T12:00:00.999999999Z", ExpiresAt: "2026-10-09T12:05:00.999999999Z", VerificationEvidenceDigest: d}
	b.VerificationEvidence = &generated.AccessVerificationEvidence{Schema: generated.SchemaIDAccessVerificationEvidence, SchemaVersion: "1.0.0", ApplyReceiptDigest: d, RollbackRecordDigest: d, ProbeResultsDigest: d, SequenceDigest: d, ExpiresAt: b.ExpiresAt}
	envelope := generated.HostActionEnvelope{Schema: generated.SchemaIDHostActionEnvelope, SchemaVersion: "1.0.0", Bundle: b, KeyID: id, Signature: strings.Repeat("a", 88)}
	encoded, e := json.Marshal(envelope)
	if e != nil || len(encoded) > hostaction.MaximumEnvelope {
		return fmt.Errorf("%w: envelope capacity", errInput)
	}
	return nil
}
