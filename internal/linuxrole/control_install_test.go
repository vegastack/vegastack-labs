package linuxrole

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestControlHandoffRejectsChangedIdentity(t *testing.T) {
	h := &generated.ControlHandoffInput{ServiceUID: 1001, ForegroundPID: 234, ForegroundStartIdentity: "boot:99", DatabaseInstanceID: "instance", RecoveryEpoch: 3, WriterLockDigest: "lock", UnitDigest: "unit", ConfigDigest: "config", ExecutableDigest: "exe", SocketIdentityDigest: "socket"}
	in := generated.LinuxRoleInput{RoleID: "control", Handoff: h}
	s := ControlServiceState{ServiceUID: 1001, PID: 234, StartIdentity: "boot:99", DatabaseInstanceID: "instance", RecoveryEpoch: 3, WriterLockDigest: "lock", UnitDigest: "unit", ConfigDigest: "config", ExecutableDigest: "exe", SocketIdentityDigest: "socket", Healthy: true}
	if ValidateControlHandoff(in, s) != nil {
		t.Fatal("exact foreground rejected")
	}
	for name, change := range map[string]func(*ControlServiceState){"pid": func(s *ControlServiceState) { s.PID++ }, "reuse": func(s *ControlServiceState) { s.StartIdentity = "boot:100" }, "root": func(s *ControlServiceState) { s.ServiceUID = 0 }, "epoch": func(s *ControlServiceState) { s.RecoveryEpoch++ }, "database": func(s *ControlServiceState) { s.DatabaseInstanceID = "different" }, "unit": func(s *ControlServiceState) { s.UnitDigest = "changed" }, "config": func(s *ControlServiceState) { s.ConfigDigest = "changed" }, "writer": func(s *ControlServiceState) { s.WriterLockDigest = "different" }, "health": func(s *ControlServiceState) { s.Healthy = false }} {
		t.Run(name, func(t *testing.T) {
			bad := s
			change(&bad)
			if ValidateControlHandoff(in, bad) == nil {
				t.Fatal("changed binding accepted")
			}
		})
	}
}
