//go:build linux

package cijobrunner

import (
	"strings"
	"testing"
)

func TestRootVolumeDoesNotCopyDistribution(t *testing.T) {
	a := jobCreateArgs(Spec{}, RuntimeProfile{Offline: true, NetworkID: "none", MemoryBytes: 268435456, CPUQuotaMicros: 50000, CPUPeriodMicros: 100000, PidsLimit: 64}, []string{"root", "bin", "externals", "tools"}, "owned")
	s := strings.Join(a, " ")
	for _, want := range []string{"volume-nocopy", "--read-only", "--log-driver none", "1001:1001", "no-new-privileges", "dst=/vsk-ci,readonly"} {
		if !strings.Contains(s, want) {
			t.Fatal(want, s)
		}
	}
	if strings.Contains(s, "docker.sock") || strings.Contains(s, "--privileged") {
		t.Fatal(s)
	}
}
func TestInitializationChmodBeforeChown(t *testing.T) {
	if strings.Index(initCommand, "chmod 0700 /home/runner") > strings.Index(initCommand, "chown 1001:1001 /home/runner") {
		t.Fatal("CHOWN-only init requires chmod first")
	}
}
