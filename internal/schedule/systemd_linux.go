//go:build linux

package schedule

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type RunnerProfile struct {
	UID                                 uint32
	PrincipalID, BinaryPath, ConfigPath string
}
type UnitSet struct {
	ServiceName, TimerName, Service, Timer, Digest string
}

var unitID = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)
var unitPath = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

func RenderSystemd(policy generated.ScheduledJobPolicy, runner RunnerProfile) (UnitSet, error) {
	if _, _, err := CanonicalPolicy(policy); err != nil {
		return UnitSet{}, err
	}
	if runner.UID == 0 || !unitID.MatchString(runner.PrincipalID) || !filepath.IsAbs(runner.BinaryPath) || !filepath.IsAbs(runner.ConfigPath) || !unitPath.MatchString(runner.BinaryPath) || !unitPath.MatchString(runner.ConfigPath) || strings.ContainsAny(runner.BinaryPath+runner.ConfigPath, "\n\r\x00\"") {
		return UnitSet{}, errors.New("invalid scheduled runner profile")
	}
	name := "vsk-labs-schedule-" + policy.PolicyID
	service := fmt.Sprintf("[Unit]\nDescription=VegaStack exact scheduled policy %s\n[Service]\nType=oneshot\nUser=%d\nExecStart=%s schedule dispatch --config %s --policy-id %s --output json\nRestart=no\nTimeoutStartSec=%d\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectControlGroups=yes\nRestrictAddressFamilies=AF_UNIX\nStandardOutput=journal\nStandardError=journal\n", policy.PolicyID, runner.UID, runner.BinaryPath, runner.ConfigPath, policy.PolicyID, policy.WindowSeconds)
	timer := fmt.Sprintf("[Unit]\nDescription=Wake VegaStack exact scheduled policy %s\n[Timer]\nOnBootSec=1min\nOnUnitActiveSec=%ds\nPersistent=false\nUnit=%s.service\n[Install]\nWantedBy=timers.target\n", policy.PolicyID, policy.IntervalSeconds, name)
	sum := sha256.Sum256([]byte(service + timer))
	return UnitSet{ServiceName: name + ".service", TimerName: name + ".timer", Service: service, Timer: timer, Digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}
