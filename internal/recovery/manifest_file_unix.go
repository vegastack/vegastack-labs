//go:build linux || darwin

package recovery

import (
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const systemAdminRootPath = "/etc/vsk-labs/recovery/admin-root.pub"
const systemWitnessManifestPath = "/etc/vsk-labs/recovery/witness-manifest.json"

// LoadSystemWitnessManifest reads only fixed OS-profile paths. Neither path
// comes from a restore request, restored SQLite, or the signed artifact.
func LoadSystemWitnessManifest(expected WitnessBinding) (PinnedWitness, error) {
	// A root-running controller can rewrite an admin-owned public pin; it
	// therefore cannot claim independent OS custody from this file source.
	if os.Geteuid() == 0 {
		return PinnedWitness{}, ErrWitnessUnavailable
	}
	root, err := readProtectedWitnessFile(systemAdminRootPath, 0, ed25519.PublicKeySize)
	if err != nil || len(root) != ed25519.PublicKeySize {
		return PinnedWitness{}, ErrWitnessUnavailable
	}
	manifest, err := readProtectedWitnessFile(systemWitnessManifestPath, 0, 16384)
	if err != nil {
		return PinnedWitness{}, ErrWitnessUnavailable
	}
	return ParseSignedRecoveryManifest(manifest, root, expected, time.Now().UTC())
}

func readProtectedWitnessFile(path string, uid uint32, max int) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || max < 1 || max > 1<<20 {
		return nil, ErrWitnessUnavailable
	}
	parentFD, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrWitnessUnavailable
	}
	defer unix.Close(parentFD)
	var parent unix.Stat_t
	if unix.Fstat(parentFD, &parent) != nil || parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Uid != uid || parent.Mode&0o022 != 0 {
		return nil, ErrWitnessUnavailable
	}
	fd, err := unix.Openat(parentFD, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrWitnessUnavailable
	}
	file := os.NewFile(uintptr(fd), "protected-witness-artifact")
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrWitnessUnavailable
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uid || stat.Mode&0o022 != 0 || stat.Nlink != 1 || stat.Size < 1 || stat.Size > int64(max) {
		return nil, ErrWitnessUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(max)+1))
	if err != nil || len(data) != int(stat.Size) {
		return nil, ErrWitnessUnavailable
	}
	return data, nil
}
