//go:build linux

package qualification

import (
	"os"
	"strings"
	"testing"
)

func TestNativeExecutionRequiresCurrentPhysicalKernelBoot(t *testing.T) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := validateScope(scopeFixture())
	if err != nil {
		t.Fatal(err)
	}
	scope.value.PhysicalHostBootID = strings.TrimSpace(string(raw))
	if validateOuterPhysicalHost(scope) != nil {
		t.Fatal("actual current physical boot rejected")
	}
	scope.value.PhysicalHostBootID = "11111111-1111-1111-1111-111111111111"
	if strings.TrimSpace(string(raw)) == scope.value.PhysicalHostBootID {
		t.Fatal("test sentinel collides with actual host")
	}
	if validateOuterPhysicalHost(scope) == nil {
		t.Fatal("scope from another host/boot accepted")
	}
	for _, invalid := range []string{"", "00000000-0000-0000-0000-000000000000", "caller-supplied-hostname", string(raw) + "extra"} {
		if physicalBootMatches(invalid, raw) {
			t.Fatal("invalid physical pin accepted")
		}
	}
	if physicalBootMatches(strings.TrimSpace(string(raw)), []byte(strings.Repeat("x", 129))) {
		t.Fatal("oversize physical measurement accepted")
	}
}
