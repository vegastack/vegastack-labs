//go:build linux

package qualification

import (
	"os"
	"regexp"
	"strings"
)

var nativeBootUUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// Preparation records this host-kernel boot ID in the same authenticated
// preflight that resolves the approved physical identity. Docker's private PID,
// network and cgroup namespaces do not create another kernel boot identity.
// A prepared scope moved to another host (or retained across host reboot) must
// fail before the coordinator connects to or operates any guest. This is a
// measured execution binding, not a substitute for the operator's scoped grant.
func validateOuterPhysicalHost(scope validatedNativeScope) error {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || !physicalBootMatches(scope.value.PhysicalHostBootID, raw) {
		return ErrUnavailable
	}
	return nil
}

func physicalBootMatches(expected string, actual []byte) bool {
	if len(actual) > 128 || !nativeBootUUID.MatchString(expected) || expected == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	measured := strings.TrimSpace(string(actual))
	return nativeBootUUID.MatchString(measured) && measured == expected
}
