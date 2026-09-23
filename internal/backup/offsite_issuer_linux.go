//go:build linux

package backup

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// SealedBearerFile places the one-run bearer in an inherited anonymous sealed
// descriptor suitable for AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE.
func SealedBearerFile(bearer []byte) (*os.File, error) {
	if len(bearer) < 32 || len(bearer) > 4096 {
		return nil, errors.New("invalid one-run bearer")
	}
	fd, err := unix.MemfdCreate("vsk-offsite-bearer", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "offsite-bearer")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("bearer descriptor unavailable")
	}
	if _, err = file.Write(bearer); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err = file.Seek(0, 0); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
