package linuxrole

import "github.com/vegastack/vegastack-labs/internal/generated"

// ControlServiceState contains observed identities, never an admission claim.
type ControlServiceState struct {
	DatabaseInstanceID   string `json:"databaseInstanceId"`
	RecoveryEpoch        int64  `json:"recoveryEpoch"`
	ServiceUID           int64  `json:"serviceUid"`
	PID                  int64  `json:"pid"`
	StartIdentity        string `json:"startIdentity"`
	WriterLockDigest     string `json:"writerLockDigest"`
	UnitDigest           string `json:"unitDigest"`
	ConfigDigest         string `json:"configDigest"`
	ExecutableDigest     string `json:"executableDigest"`
	SocketIdentityDigest string `json:"socketIdentityDigest"`
	ServiceActive        bool   `json:"serviceActive"`
	Healthy              bool   `json:"healthy"`
}

func ValidateControlHandoff(in generated.LinuxRoleInput, s ControlServiceState) error {
	h := in.Handoff
	if h == nil || in.RoleID != "control" || s.ServiceUID <= 0 || s.ServiceUID != h.ServiceUID || s.DatabaseInstanceID != h.DatabaseInstanceID || s.RecoveryEpoch != h.RecoveryEpoch || s.WriterLockDigest != h.WriterLockDigest || s.UnitDigest != h.UnitDigest || s.ConfigDigest != h.ConfigDigest || s.ExecutableDigest != h.ExecutableDigest || s.SocketIdentityDigest != h.SocketIdentityDigest || !s.Healthy {
		return errNative
	}
	if !s.ServiceActive && (s.PID != h.ForegroundPID || s.StartIdentity != h.ForegroundStartIdentity) {
		return errNative
	}
	if s.ServiceActive && (s.PID <= 1 || s.PID == h.ForegroundPID && s.StartIdentity == h.ForegroundStartIdentity) {
		return errNative
	}
	return nil
}
