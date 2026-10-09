//go:build linux

package qualification

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"strings"
)

// MeasureControllerIdentity binds only this controller's native consumers.
// Caller-supplied host IDs cannot select a different physical guest.
func MeasureControllerIdentity(ctx context.Context, s generated.QualificationScope, instance string) (generated.NativeControllerIdentity, error) {
	var zero generated.NativeControllerIdentity
	installed, err := LoadServerScope(ctx)
	if err != nil || hostaction.Digest(installed) != hostaction.Digest(s) || instance == "" {
		return zero, ErrUnavailable
	}
	executable, err := fileDigest("/proc/self/exe", 256<<20)
	if err != nil || executable != s.ExecutableDigest {
		return zero, ErrUnavailable
	}
	return measureControllerIdentityFiles(s, instance, executable, "/etc/machine-id", "/etc/ssh/ssh_host_ed25519_key.pub")
}

// The server cannot read root-only DMI. Its actual readable machine identity
// and host key join the root-prepared scope; the independent authenticated
// console remeasures DMI, machine identity and boot ID before observer replies.
func measureControllerIdentityFiles(s generated.QualificationScope, instance, executable, machinePath, keyPath string) (generated.NativeControllerIdentity, error) {
	var zero generated.NativeControllerIdentity
	raw, err := fixtureRootFile(machinePath, 128)
	machine := strings.TrimSpace(string(raw))
	if err != nil || !nativeMachineID(machine) {
		return zero, ErrUnavailable
	}
	var found *generated.QualificationGuest
	for i := range s.Guests {
		g := &s.Guests[i]
		if (g.Role == "controller" || g.Role == "replacement") && g.MachineID == machine && verifyGuestSSHKey(*g, keyPath) == nil {
			if found != nil {
				return zero, ErrUnavailable
			}
			found = g
		}
	}
	if found == nil {
		return zero, ErrUnavailable
	}
	return generated.NativeControllerIdentity{Schema: generated.SchemaIDNativeControllerIdentity, SchemaVersion: "1.0.0", HostID: found.HostID, HostIdentityDigest: found.HostIdentityDigest, HostMachineID: machine, ControllerInstanceID: instance, ScopeDigest: hostaction.Digest(s), ExecutableDigest: executable}, nil
}
func nativeMachineID(machine string) bool {
	if len(machine) != 32 {
		return false
	}
	for _, c := range machine {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return machine != "00000000000000000000000000000000"
}
