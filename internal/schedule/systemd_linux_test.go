//go:build linux

package schedule

import (
	"strings"
	"testing"
)

func TestRenderedTimerIsWakeupOnlyAndHardened(t *testing.T) {
	units, err := RenderSystemd(validPolicy(), RunnerProfile{UID: 991, PrincipalID: "schedule-runner", BinaryPath: "/usr/local/bin/vsk-labs", ConfigPath: "/etc/vegastack/server.json"})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"Type=oneshot", "Restart=no", "NoNewPrivileges=yes", "ProtectSystem=strict", "RestrictAddressFamilies=AF_UNIX", "schedule dispatch", "--policy-id policy-a"} {
		if !strings.Contains(units.Service+units.Timer, required) {
			t.Errorf("missing %q", required)
		}
	}
	for _, forbidden := range []string{"/bin/sh", "Environment=", "Restart=always", "backup.restore", "--target-id", "--adapter-id", "Persistent=true"} {
		if strings.Contains(units.Service+units.Timer, forbidden) {
			t.Errorf("forbidden %q", forbidden)
		}
	}
}

func TestRenderedTimerRejectsSystemdSignificantPaths(t *testing.T) {
	for _, path := range []string{"/opt/vsk labs/vsk-labs", "/opt/vsk%N/vsk-labs", `/opt/vsk\\labs`} {
		if _, err := RenderSystemd(validPolicy(), RunnerProfile{UID: 991, PrincipalID: "schedule-runner", BinaryPath: path, ConfigPath: "/etc/vegastack/server.json"}); err == nil { t.Fatalf("accepted %q",path) }
	}
}
