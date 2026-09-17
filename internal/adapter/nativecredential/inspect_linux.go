//go:build linux

package nativecredential

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type InspectRequest struct {
	Name, CiphertextDirectory string
	ExpectedUID               uint32
}

type CiphertextInspection struct {
	State, Fingerprint string
}

func InspectEncrypted(ctx context.Context, request InspectRequest) (CiphertextInspection, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(request.CiphertextDirectory) || filepath.Clean(request.CiphertextDirectory) != request.CiphertextDirectory {
		return CiphertextInspection{}, nativeError(generated.ErrorCodeInputInvalid, "ciphertext-inspection")
	}
	if _, err := credentialref.ParseID(request.Name); err != nil {
		return CiphertextInspection{}, nativeError(generated.ErrorCodeInputInvalid, "credential-name")
	}
	directoryFD, err := unix.Open(request.CiphertextDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return CiphertextInspection{}, nativeError(generated.ErrorCodePrerequisiteBlocked, "ciphertext-directory")
	}
	defer unix.Close(directoryFD)
	var directory unix.Stat_t
	if unix.Fstat(directoryFD, &directory) != nil || directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Uid != request.ExpectedUID || directory.Mode&0o777 != 0o700 {
		return CiphertextInspection{}, nativeError(generated.ErrorCodeAuthorizationDenied, "ciphertext-directory")
	}
	fileFD, err := unix.Openat(directoryFD, request.Name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return CiphertextInspection{State: "absent"}, nil
	}
	if err != nil {
		return CiphertextInspection{}, nativeError(generated.ErrorCodeRecoveryRequired, "ciphertext-inspection")
	}
	file := os.NewFile(uintptr(fileFD), "credential-ciphertext")
	if file == nil {
		_ = unix.Close(fileFD)
		return CiphertextInspection{}, nativeError(generated.ErrorCodeRecoveryRequired, "ciphertext-inspection")
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fileFD, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != request.ExpectedUID || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 || stat.Size < 16 || stat.Size > 8192 {
		return CiphertextInspection{}, nativeError(generated.ErrorCodeRecoveryRequired, "ciphertext-file")
	}
	ciphertext, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(ciphertext) < 16 || len(ciphertext) > 8192 || ctx.Err() != nil {
		return CiphertextInspection{}, nativeError(generated.ErrorCodeRecoveryRequired, "ciphertext-file")
	}
	sum := sha256.Sum256(ciphertext)
	return CiphertextInspection{State: "present", Fingerprint: "sha256:" + hex.EncodeToString(sum[:])}, nil
}
