//go:build linux

package nativecredential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const hostKeyPath = "/var/lib/systemd/credential.secret"
const credsCommandPath = "/usr/bin/systemd-creds"

// StageRequest binds an encrypted file name to one consumer/reference/version.
// HostKeyPath is an isolated-fixture override only: StageEncrypted refuses any
// production value other than the systemd host-key location.
type StageRequest struct {
	Name, CiphertextDirectory string
	ExpectedUID               uint32
	HostKeyPath               string
}

type encryptRunner interface {
	Run(context.Context, []string, []byte, string) error
}
type systemdEncryptRunner struct{}

func (systemdEncryptRunner) Run(ctx context.Context, args []string, input []byte, output string) error {
	command := exec.CommandContext(ctx, credsCommandPath, args...)
	command.Stdin = bytes.NewReader(input)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.Env = []string{"LANG=C", "PATH=/usr/bin:/bin"}
	return command.Run()
}

func StageEncrypted(ctx context.Context, input io.Reader, request StageRequest) (string, error) {
	if request.HostKeyPath != "" && request.HostKeyPath != hostKeyPath {
		return "", nativeError(generated.ErrorCodeInputInvalid, "host-key-override")
	}
	request.HostKeyPath = hostKeyPath
	return stageEncryptedWithRunner(ctx, input, request, systemdEncryptRunner{})
}

func nativeError(code, target string) error { return failure.New(code, target, false) }

func stageEncryptedWithRunner(ctx context.Context, input io.Reader, request StageRequest, runner encryptRunner) (string, error) {
	if ctx == nil || input == nil || runner == nil || request.HostKeyPath == "" || !filepath.IsAbs(request.HostKeyPath) || filepath.Clean(request.HostKeyPath) != request.HostKeyPath || !filepath.IsAbs(request.CiphertextDirectory) || filepath.Clean(request.CiphertextDirectory) != request.CiphertextDirectory {
		return "", nativeError(generated.ErrorCodeInputInvalid, "native-stage")
	}
	if _, err := credentialref.ParseID(request.Name); err != nil {
		return "", nativeError(generated.ErrorCodeInputInvalid, "credential-name")
	}
	key, err := os.Lstat(request.HostKeyPath)
	if err != nil || !key.Mode().IsRegular() || key.Mode().Perm()&0o077 != 0 || key.Size() < 32 || key.Size() > 8192 {
		return "", nativeError(generated.ErrorCodePrerequisiteBlocked, "native-host-key")
	}
	keyStat, okay := key.Sys().(*syscall.Stat_t)
	if !okay || keyStat.Uid != 0 && keyStat.Uid != request.ExpectedUID {
		return "", nativeError(generated.ErrorCodeAuthorizationDenied, "native-host-key")
	}
	directory, err := os.Lstat(request.CiphertextDirectory)
	if err != nil || !directory.IsDir() || directory.Mode().Perm()&0o077 != 0 {
		return "", nativeError(generated.ErrorCodeAuthorizationDenied, "ciphertext-directory")
	}
	directoryStat, okay := directory.Sys().(*syscall.Stat_t)
	if !okay || directoryStat.Uid != request.ExpectedUID {
		return "", nativeError(generated.ErrorCodeAuthorizationDenied, "ciphertext-directory")
	}
	private, err := io.ReadAll(io.LimitReader(input, 4097))
	if err != nil || len(private) < 8 || len(private) > 4096 {
		wipe(private)
		return "", nativeError(generated.ErrorCodeInputInvalid, "credential-input")
	}
	defer wipe(private)
	final := filepath.Join(request.CiphertextDirectory, request.Name)
	if _, err := os.Lstat(final); err == nil {
		return "", nativeError(generated.ErrorCodeStateConflict, "credential-version-exists")
	} else if !os.IsNotExist(err) {
		return "", nativeError(generated.ErrorCodeDependencyUnavailable, "ciphertext-directory")
	}
	temp, err := os.CreateTemp(request.CiphertextDirectory, "."+request.Name+"-staging-")
	if err != nil {
		return "", nativeError(generated.ErrorCodeDependencyUnavailable, "ciphertext-stage")
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return "", nativeError(generated.ErrorCodeDependencyUnavailable, "ciphertext-stage")
	}
	if err := temp.Close(); err != nil {
		return "", nativeError(generated.ErrorCodeDependencyUnavailable, "ciphertext-stage")
	}
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	args := []string{"encrypt", "--with-key=host", "--name=" + request.Name, "-", tempPath}
	if err := runner.Run(deadline, args, private, tempPath); err != nil {
		return "", nativeError(generated.ErrorCodeDependencyUnavailable, "systemd-creds-encrypt")
	}
	// systemd-creds may recreate the target under its inherited umask (022).
	// The enclosing 0700 directory prevents access during that short window;
	// normalize the newly written regular ciphertext to 0600 before promotion.
	staged, err := os.Lstat(tempPath)
	if err != nil || !staged.Mode().IsRegular() || staged.Size() < 16 || staged.Size() > 8192 {
		return "", nativeError(generated.ErrorCodeIntegrityFailure, "ciphertext-envelope")
	}
	stagedStat, okay := staged.Sys().(*syscall.Stat_t)
	if !okay || stagedStat.Uid != request.ExpectedUID || os.Chmod(tempPath, 0o600) != nil {
		return "", nativeError(generated.ErrorCodeAuthorizationDenied, "ciphertext-owner")
	}
	fd, err := unix.Open(tempPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", nativeError(generated.ErrorCodeDependencyUnavailable, "ciphertext-stage")
	}
	output := os.NewFile(uintptr(fd), "staged-ciphertext")
	info, err := output.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 16 || info.Size() > 8192 {
		_ = output.Close()
		return "", nativeError(generated.ErrorCodeIntegrityFailure, "ciphertext-envelope")
	}
	outputStat, okay := info.Sys().(*syscall.Stat_t)
	if !okay || outputStat.Uid != request.ExpectedUID {
		_ = output.Close()
		return "", nativeError(generated.ErrorCodeAuthorizationDenied, "ciphertext-owner")
	}
	ciphertext, err := io.ReadAll(io.LimitReader(output, 8193))
	if err != nil || len(ciphertext) < 16 || len(ciphertext) > 8192 || bytes.Contains(ciphertext, private) {
		_ = output.Close()
		return "", nativeError(generated.ErrorCodeIntegrityFailure, "ciphertext-envelope")
	}
	sum := sha256.Sum256(ciphertext)
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return "", nativeError(generated.ErrorCodeDependencyUnavailable, "ciphertext-sync")
	}
	if err := output.Close(); err != nil {
		return "", nativeError(generated.ErrorCodeDependencyUnavailable, "ciphertext-sync")
	}
	if err := unix.Renameat2(unix.AT_FDCWD, tempPath, unix.AT_FDCWD, final, unix.RENAME_NOREPLACE); err != nil {
		return "", nativeError(generated.ErrorCodeStateConflict, "credential-version-exists")
	}
	if dir, err := os.Open(request.CiphertextDirectory); err != nil {
		return "", nativeError(generated.ErrorCodeDependencyUnavailable, "ciphertext-sync")
	} else {
		syncErr := dir.Sync()
		_ = dir.Close()
		if syncErr != nil {
			return "", nativeError(generated.ErrorCodeDependencyUnavailable, "ciphertext-sync")
		}
	}
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
