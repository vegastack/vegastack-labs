//go:build linux

package server

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/vegastack/vegastack-labs/internal/recovery"
)

const recoveryRecipientCredentialName = "recovery-recipient-x25519-v1"

// systemdRecoveryRecipientKeySource reads only one fixed systemd-loaded
// credential. The service profile must provision it separately under the
// replacement host's native protected credential directory; no request can
// choose a key path or reveal its bytes in public output.
type systemdRecoveryRecipientKeySource struct{ ownerUID uint32 }

func (source systemdRecoveryRecipientKeySource) OpenPrivate(ctx context.Context, keyID string) (io.ReadCloser, error) {
	if ctx == nil || ctx.Err() != nil || keyID == "" {
		return nil, recovery.ErrWitnessUnavailable
	}
	directoryPath := os.Getenv("CREDENTIALS_DIRECTORY")
	if !filepath.IsAbs(directoryPath) || filepath.Clean(directoryPath) != directoryPath {
		return nil, recovery.ErrWitnessUnavailable
	}
	directoryFD, err := unix.Open(directoryPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, recovery.ErrWitnessUnavailable
	}
	defer unix.Close(directoryFD)
	var directory unix.Stat_t
	if unix.Fstat(directoryFD, &directory) != nil || directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Uid != source.ownerUID || directory.Mode&0o777 != 0o700 {
		return nil, recovery.ErrWitnessUnavailable
	}
	fd, err := unix.Openat(directoryFD, recoveryRecipientCredentialName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, recovery.ErrWitnessUnavailable
	}
	file := os.NewFile(uintptr(fd), "protected-recovery-recipient")
	if file == nil {
		_ = unix.Close(fd)
		return nil, recovery.ErrWitnessUnavailable
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != source.ownerUID || stat.Mode&0o777 != 0o400 && stat.Mode&0o777 != 0o600 || stat.Nlink != 1 || stat.Size != 32 || ctx.Err() != nil {
		_ = file.Close()
		return nil, recovery.ErrWitnessUnavailable
	}
	return file, nil
}
