//go:build linux

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func readSystemRecoveryCanaryCapabilityConfig() (recoveryCanaryCapabilityConfig, error) {
	blocked := func() (recoveryCanaryCapabilityConfig, error) {
		return recoveryCanaryCapabilityConfig{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-capability", false)
	}
	path := systemRecoveryCanaryConfigPath
	parentFD, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return blocked()
	}
	defer unix.Close(parentFD)
	var parent unix.Stat_t
	if unix.Fstat(parentFD, &parent) != nil || parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Uid != 0 || parent.Mode&0o022 != 0 {
		return blocked()
	}
	fd, err := unix.Openat(parentFD, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return blocked()
	}
	file := os.NewFile(uintptr(fd), "recovery-canary-capabilities")
	if file == nil {
		_ = unix.Close(fd)
		return blocked()
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0o022 != 0 || stat.Nlink != 1 || stat.Size < 1 || stat.Size > 64*1024 {
		return blocked()
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil || len(raw) != int(stat.Size) {
		return blocked()
	}
	var config recoveryCanaryCapabilityConfig
	if json.Unmarshal(raw, &config) != nil {
		return blocked()
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, raw) {
		return blocked()
	}
	return config, nil
}
