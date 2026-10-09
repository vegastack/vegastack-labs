package qualification

import (
	"context"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

// The disposable supervisor may activate only its already prepared action
// signer and, when prepared, the existing local backup backend. The socket,
// principals, adapters and every other setting stay exact.
func validateFixtureSignerProfiles(initial, final []byte, uid uint32, pin string) error {
	if hostaction.BytesDigest(initial) != pin {
		return ErrUnavailable
	}
	var before, after generated.ServerProfile
	for _, input := range []struct {
		raw []byte
		out *generated.ServerProfile
	}{{initial, &before}, {final, &after}} {
		if generated.ValidateContractJSON(generated.SchemaIDServerProfile, input.raw, generated.ContractExact) != nil || fixtureDecode(context.Background(), input.raw, input.out, 65536) != nil {
			return ErrUnavailable
		}
		if _, err := serverconfig.DecodeProfile(input.raw, uid); err != nil {
			return ErrUnavailable
		}
	}
	if before.StandardBackupRoot != nil || before.CriticalBackupRoot != nil || before.ResticBinaryPath != nil || before.CustodyPolicyPath != nil || before.HostActionSignerPath != "" || before.HostActionKeyID != "" || len(before.HostActionIdentityDigests) != 0 || after.HostActionSignerPath != fixtureControlSignerPath || after.HostActionKeyID == "" || len(after.HostActionIdentityDigests) == 0 {
		return ErrUnavailable
	}
	after.StandardBackupRoot, after.CriticalBackupRoot, after.ResticBinaryPath, after.CustodyPolicyPath = nil, nil, nil, nil
	after.HostActionSignerPath = ""
	after.HostActionKeyID = ""
	after.HostActionIdentityDigests = before.HostActionIdentityDigests
	if hostaction.Digest(before) != hostaction.Digest(after) {
		return ErrUnavailable
	}
	return nil
}

const fixtureControlSignerPath = "/etc/vsk-labs/control/action-signing.key"

func fixtureSetupProfileMatches(review json.RawMessage, digest string) bool {
	var value struct {
		Request generated.LocalSetupReviewRequest `json:"request"`
	}
	return json.Unmarshal(review, &value) == nil && value.Request.ProfileSHA256 == digest && digest != ""
}
