//go:build linux

package server

import (
	"crypto/tls"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func loadProtectedTLSKeyPair(certificatePath, privateKeyPath string) (tls.Certificate, error) {
	certificatePEM, err := readProtectedTLSMaterial(certificatePath, false)
	if err != nil {
		return tls.Certificate{}, err
	}
	privateKeyPEM, err := readProtectedTLSMaterial(privateKeyPath, true)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer clear(privateKeyPEM)
	return tls.X509KeyPair(certificatePEM, privateKeyPEM)
}

func readProtectedTLSMaterial(materialPath string, private bool) ([]byte, error) {
	descriptor, err := unix.Openat2(unix.AT_FDCWD, materialPath, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), "remote-tls-material")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, unix.EBADF
	}
	defer file.Close()
	var status unix.Stat_t
	if err := unix.Fstat(descriptor, &status); err != nil || status.Mode&unix.S_IFMT != unix.S_IFREG || status.Nlink != 1 || status.Uid != uint32(os.Geteuid()) || status.Size <= 0 || status.Size > maxTLSMaterialBytes {
		return nil, unix.EPERM
	}
	permissions := status.Mode & 0o777
	if (private && permissions != 0o600) || (!private && permissions != 0o600 && permissions != 0o640 && permissions != 0o644) {
		return nil, unix.EPERM
	}
	content, err := io.ReadAll(io.LimitReader(file, maxTLSMaterialBytes+1))
	if err != nil || len(content) == 0 || len(content) > maxTLSMaterialBytes {
		return nil, unix.EIO
	}
	return content, nil
}
