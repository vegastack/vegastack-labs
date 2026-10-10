//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
)

// This edits only the isolated wire peer's exact card allowlist. The ordinary
// acknowledgement service still receives and authorizes the Slack interaction.
func publishFixtureApproval(ctx context.Context, scope validatedNativeScope, in generated.NativePreparationRequest) error {
	if os.Geteuid() != 0 || in.FixtureApproval == nil || ownedDirectory(slackFixtureDirectory, 0) != nil {
		return ErrUnavailable
	}
	raw, err := ownedFile(slackFixtureDirectory+"/slack-fixture.json", 0, 32768)
	var fixture generated.NativeSlackFixtureScope
	if err != nil || !exactFixtureDecode(raw, generated.SchemaIDNativeSlackFixtureScope, &fixture) {
		return ErrUnavailable
	}
	now := time.Now().UTC()
	start, e := time.Parse(time.RFC3339, fixture.IssuedAt)
	end, f := time.Parse(time.RFC3339, fixture.ExpiresAt)
	scopeEnd, _ := time.Parse(time.RFC3339, scope.value.ExpiresAt)
	if e != nil || f != nil || now.Before(start) || !now.Before(end) || end.Sub(start) > 4*time.Hour || end.After(scopeEnd) || fixture.SourceCommit != scope.value.SourceCommit || fixture.ExecutableDigest != scope.value.ExecutableDigest {
		return ErrUnavailable
	}
	matched := false
	for _, g := range scope.guests {
		if (g.Role == "controller" || g.Role == "replacement") && g.InstanceID == fixture.GuestInstanceID && g.HostIdentityDigest == fixture.HostIdentityDigest && g.SSHHostKeyDigest == fixture.SSHHostKeyDigest && verifyLocalGuest(g) == nil {
			matched = true
		}
	}
	if !matched {
		return ErrUnavailable
	}
	machine, err := fixtureRootFile("/etc/machine-id", 128)
	if err != nil || hostaction.BytesDigest([]byte(trimMachineID(machine))) != fixture.SetupHostIdentityDigest {
		return ErrUnavailable
	}
	actual, err := fileDigest("/proc/self/exe", 256<<20)
	if err != nil || actual != fixture.ExecutableDigest {
		return ErrUnavailable
	}
	reply, err := callNativeAPI(ctx, scope, nativeAPIPacket{Step: in.Binding, Kind: "fixture-plan", Preparation: &in})
	if err != nil || reply.Plan == nil {
		return ErrUnavailable
	}
	if validateFixtureApproval(*in.FixtureApproval, *reply.Plan, fixture, in.Binding.RecoveryEpoch, time.Now().UTC()) != nil {
		return ErrUnavailable
	}
	// A fixed exclusive lock serializes publication; a crash leaves a fail-closed
	// fixture rather than enabling a second writer or replacing an unknown file.
	lock, err := os.OpenFile(slackFixtureDirectory+"/approvals.lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrUnavailable
	}
	_ = lock.Close()
	defer os.Remove(slackFixtureDirectory + "/approvals.lock")
	raw, err = ownedFile(slackFixtureDirectory+"/approvals.json", 0, 65536)
	var list generated.NativeSlackFixtureApprovalList
	if err != nil || !exactFixtureDecode(raw, generated.SchemaIDNativeSlackFixtureApprovalList, &list) {
		return ErrUnavailable
	}
	if err = replaceFixtureApproval(&list, *in.FixtureApproval); err != nil {
		return err
	}
	raw, err = json.Marshal(list)
	if err != nil || len(raw) > 65536 {
		return ErrUnavailable
	}
	tmp := slackFixtureDirectory + "/approvals.publishing"
	fd, err := unix.Open(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), tmp)
	defer os.Remove(tmp)
	_, err = file.Write(raw)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return ErrUnavailable
	}
	if err = os.Rename(tmp, slackFixtureDirectory+"/approvals.json"); err != nil {
		return ErrUnavailable
	}
	return nil
}

func exactFixtureDecode(raw []byte, schema string, out any) bool {
	return generated.ValidateContractJSON(schema, raw, generated.ContractExact) == nil && fixtureDecode(context.Background(), raw, out, 65536) == nil
}
