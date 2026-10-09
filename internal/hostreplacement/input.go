// Package hostreplacement validates bounded replacement intent. These checks
// confer no authority: the server must resolve every asserted current binding.
package hostreplacement

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"golang.org/x/crypto/ssh"
)

const MaximumInput = 32768
const AdapterID = "core.host-replacement"
const FreezeOperation = "host.replacement.freeze"
const CommitOperation = "host.replacement.commit"
const AliasClaimOperation = "host.alias.claim"
const ReplacementExtension = "x-host-replacement"
const AliasClaimExtension = "x-host-alias-claim"

var errInput = errors.New("invalid host replacement input")
var canonicalID = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)

func decode(raw []byte, schema string, out any) error {
	if len(raw) == 0 || len(raw) > MaximumInput || strictjson.Scan(context.Background(), raw, strictjson.Limits{MaxDepth: 16}) != nil || generated.ValidateContractJSON(schema, raw, generated.ContractExact) != nil || json.Unmarshal(raw, out) != nil {
		return errInput
	}
	return nil
}
func DecodeInput(raw []byte) (generated.HostReplacementRequest, error) {
	var in generated.HostReplacementRequest
	if err := decode(raw, generated.SchemaIDHostReplacementRequest, &in); err != nil {
		return in, err
	}
	return in, ValidateInput(in)
}
func ValidateInput(in generated.HostReplacementRequest) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return errInput
	}
	var checked generated.HostReplacementRequest
	if decode(raw, generated.SchemaIDHostReplacementRequest, &checked) != nil {
		return errInput
	}
	if in.OldHostID == in.NewHostID || in.OldIdentityDigest == in.NewIdentityDigest || in.OldSSHHostKeyDigest == in.NewSSHHostKeyDigest || in.OldTargetDigest == in.NewTargetDigest || !validID(in.OldHostID) || !validID(in.NewHostID) || in.OSPreparation.HostIdentityDigest != in.NewIdentityDigest {
		return errInput
	}
	if (in.RestorationClass == "stateless-role" && (in.Source != nil || len(in.PayloadIDs) != 0)) || (in.RestorationClass == "control-database" && in.Source == nil) {
		return errInput
	}
	var last string
	var generation int64
	for _, a := range in.AliasBindings {
		if !validID(a.AliasID) || a.AliasID <= last || a.OwnerHostID != in.OldHostID || a.OwnerIdentityDigest != in.OldIdentityDigest || (generation != 0 && generation != a.OwnershipGeneration) {
			return errInput
		}
		last = a.AliasID
		generation = a.OwnershipGeneration
	}
	for _, ids := range [][]string{in.PayloadIDs, in.VolumeIDs, in.ResourceIDs} {
		if !sortedIDs(ids) {
			return errInput
		}
	}
	return nil
}
func DecodeAliasClaim(raw []byte) (generated.HostAliasClaimRequest, error) {
	var in generated.HostAliasClaimRequest
	if err := decode(raw, generated.SchemaIDHostAliasClaimRequest, &in); err != nil {
		return in, err
	}
	return in, ValidateAliasClaim(in)
}
func ValidateAliasClaim(in generated.HostAliasClaimRequest) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return errInput
	}
	var checked generated.HostAliasClaimRequest
	if decode(raw, generated.SchemaIDHostAliasClaimRequest, &checked) != nil || !validID(in.HostID) || !sortedIDs(in.AliasIDs) {
		return errInput
	}
	return nil
}
func validID(s string) bool { return canonicalID.MatchString(s) && !debianaccess.ProtectedName(s) }
func sortedIDs(ids []string) bool {
	last := ""
	for _, id := range ids {
		if !validID(id) || id <= last {
			return false
		}
		last = id
	}
	return true
}

// BindingDigest binds immutable intent, including its original recovery epoch.
// A restored continuation must independently prove the prior/current transition
// before the store compares it using the original epoch. This helper never does
// that substitution or validates a receipt on the caller's behalf.
func BindingDigest(in generated.HostReplacementRequest) string {
	in.Operation = ""
	in.ExpectedDeclarationRevision = 0
	in.ExpectedStateRevision = 0
	in.IdempotencyKey = ""
	return hostaction.Digest(in)
}

// SSHHostKeyDigest hashes canonical public key material, ignoring a comment but
// rejecting options, trailing keys and certificates. It does not fingerprint
// the administrator credential or confer trust on the supplied key.
func SSHHostKeyDigest(raw string) (string, error) {
	if len(raw) > 2048 || strings.TrimSpace(raw) == "" {
		return "", errInput
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil || len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return "", errInput
	}
	if _, cert := key.(*ssh.Certificate); cert {
		return "", errInput
	}
	return hostaction.BytesDigest(key.Marshal()), nil
}
