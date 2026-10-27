//go:build linux

package cijobrunner

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/sys/unix"
)

const ConfigPath = "/etc/vsk-labs/ci-job.json"
const WorkerMode = "ci-job-worker"

// NativeConfig is root-owned protected host configuration. No secret material.
// No online verifier is currently installed by the production constructor.
type NativeConfig struct {
	ProfileID          string         `json:"profileId"`
	RuntimeDigest      string         `json:"runtimeDigest"`
	HostID             string         `json:"hostId"`
	HostIdentityDigest string         `json:"hostIdentityDigest"`
	DaemonGID          uint32         `json:"daemonGid"`
	Docker             DockerConfig   `json:"docker"`
	Profile            RuntimeProfile `json:"profile"`
}

func LoadNativeConfig(path string) (NativeConfig, error) {
	var c NativeConfig
	if path != ConfigPath || filepath.Clean(path) != path {
		return c, ErrBlocked
	}
	for _, dir := range []string{"/etc", "/etc/vsk-labs"} {
		info, e := os.Lstat(dir)
		if e != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			return c, ErrBlocked
		}
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return c, ErrBlocked
	}
	f := os.NewFile(uintptr(fd), "CI protected config")
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || s.Sys().(*syscall.Stat_t).Uid != 0 || s.Sys().(*syscall.Stat_t).Nlink != 1 || s.Size() > 16<<10 {
		return c, ErrBlocked
	}
	raw, e := io.ReadAll(io.LimitReader(f, 16<<10+1))
	if e != nil {
		return c, ErrBlocked
	}
	if decodeFrame(context.Background(), raw, &c) != nil || !identifier.MatchString(c.ProfileID) || c.RuntimeDigest != ComputeRuntimeDigest(c.Profile) || c.Profile.DaemonUID == 0 || c.DaemonGID == 0 {
		return NativeConfig{}, ErrBlocked
	}
	return c, nil
}

// Load receives an already authorized signed bundle, then independently matches
// its runtime binding against the protected local profile. It grants no authority.
func (c NativeConfig) Load(ctx context.Context, b generated.HostActionBundle) (Spec, RuntimeProfile, error) {
	var s Spec
	if b.HostID != c.HostID || b.HostIdentityDigest != c.HostIdentityDigest || decodeFrame(ctx, []byte(b.ActionInput), &s) != nil || s.RuntimeProfileID != c.ProfileID || s.RuntimeDigest != c.RuntimeDigest || ValidateSpec(s, c.Profile) != nil {
		return s, RuntimeProfile{}, ErrBlocked
	}
	return s, c.Profile, nil
}
