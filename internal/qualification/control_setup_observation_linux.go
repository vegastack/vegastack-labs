//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

// InspectNativeControlSetup reads only the fixed temporary peer observation and
// independently rechecks its live owner, manifest and guest. Per-attempt API readiness was measured by the supervisor. It
// never accepts setup outcomes from a request and never opens the database.
func InspectNativeControlSetup(ctx context.Context) (generated.NativeControlSetupWitness, error) {
	var w generated.NativeControlSetupWitness
	if ctx == nil || ctx.Err() != nil || ownedDirectory(slackFixtureDirectory, 0) != nil {
		return w, ErrUnavailable
	}
	raw, e := ownedFile(fixtureSetupWitnessPath, 0, 65536)
	if e != nil || generated.ValidateContractJSON(generated.SchemaIDNativeControlSetupWitness, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &w) != nil {
		return w, ErrUnavailable
	}
	var s generated.NativeSlackFixtureScope
	raw, e = ownedFile(slackFixtureDirectory+"/slack-fixture.json", 0, 32768)
	if e != nil || generated.ValidateContractJSON(generated.SchemaIDNativeSlackFixtureScope, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &s) != nil || !s.RunControlSetup || hostaction.Digest(s) != w.ScopeDigest || hostaction.Digest(w.FixtureScope) != w.ScopeDigest {
		return w, ErrUnavailable
	}
	issued, e := time.Parse(time.RFC3339Nano, s.IssuedAt)
	expires, f := time.Parse(time.RFC3339Nano, s.ExpiresAt)
	now := time.Now().UTC()
	if e != nil || f != nil || now.Before(issued) || !now.Before(expires) || expires.Sub(issued) > 4*time.Hour {
		return w, ErrUnavailable
	}
	start, e := fixtureStartIdentity(int(w.PeerPID))
	if e != nil || start != w.PeerStartIdentity {
		return w, ErrUnavailable
	}
	if d, e := fileDigest("/proc/"+strconv.FormatInt(w.PeerPID, 10)+"/exe", 256<<20); e != nil || d != s.ExecutableDigest {
		return w, ErrUnavailable
	}
	if verifyLocalGuest(generated.QualificationGuest{InstanceID: s.GuestInstanceID, HostIdentityDigest: s.HostIdentityDigest, SSHHostKeyDigest: s.SSHHostKeyDigest}) != nil {
		return w, ErrUnavailable
	}
	approval, uid, mode, e := fixtureRegularFile(slackFixtureSetupPath+".approval.json", 65536)
	if e != nil || int64(uid) != s.ControlServiceUID || mode != 0600 || hostaction.BytesDigest(approval) != w.ApprovalDigest {
		return w, ErrUnavailable
	}
	var receipt struct {
		Review json.RawMessage `json:"review"`
	}
	if json.Unmarshal(approval, &receipt) != nil || hostaction.BytesDigest(receipt.Review) != w.SetupReviewDigest || !fixtureSetupProfileMatches(receipt.Review, w.InitialProfileDigest) {
		return w, ErrUnavailable
	}
	// The original controller may now be fenced by an actual restore. Do not
	// reinterpret this preserved setup observation as current health. The
	// collector independently binds the current producer and verified restore.
	return w, nil
}
