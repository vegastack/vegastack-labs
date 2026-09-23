//go:build !linux

package backup

import (
	"errors"
	"time"
)

// CustodyPolicy is Linux-only operational policy. Other platforms retain its
// shape so portable configuration can fail closed before attempting custody.
type CustodyPolicy struct {
	SchemaVersion      string        `json:"schemaVersion"`
	StandardRoot       string        `json:"standardRoot"`
	CriticalRoot       string        `json:"criticalRoot"`
	StandardQuarantine string        `json:"standardQuarantine"`
	CriticalQuarantine string        `json:"criticalQuarantine"`
	OwnerUID           uint32        `json:"ownerUid"`
	OwnerGID           uint32        `json:"ownerGid"`
	ControllerUID      uint32        `json:"controllerUid"`
	ResticUID          uint32        `json:"resticUid"`
	ExecutableDigest   string        `json:"executableDigest"`
	MaximumLifetime    time.Duration `json:"maximumLifetime"`
}

func LoadCustodyPolicy(string) (CustodyPolicy, error) {
	return CustodyPolicy{}, errors.New("repository custody requires Linux")
}

func VerifyCustodyPaths(CustodyPolicy, string) error {
	return errors.New("repository custody requires Linux")
}
