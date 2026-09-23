//go:build linux

package nativecredential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// VerifyRecoveryRequest names one already-sealed inert import draft. The
// fingerprint must come from its immutable metadata, not from the caller's
// newly staged ciphertext.
type VerifyRecoveryRequest struct {
	Name, CiphertextDirectory, ExpectedFingerprint string
	ExpectedUID                                    uint32
}

// VerifiedDraft contains public metadata only. A caller must separately
// establish independent custody, former-controller fencing, and the epoch.
type VerifiedDraft struct {
	CiphertextFingerprint string
	HostKeyDigest         string
}

// VerifyRecoveredDraft decrypts the bytes read from the exact protected draft
// inode under this host's fixed native systemd key and compares the result
// with independently supplied material. It owns and closes the supplied
// stream, including on cancellation. It grants no credential authority.
func VerifyRecoveredDraft(ctx context.Context, request VerifyRecoveryRequest, independent io.ReadCloser) (result VerifiedDraft, err error) {
	var expected [4097]byte
	var output [4097]byte
	defer func() {
		wipe(expected[:])
		wipe(output[:])
		if recover() != nil {
			result = VerifiedDraft{}
			err = nativeError(generated.ErrorCodeRecoveryRequired, "credential-recovery-verify")
		}
	}()
	if independent != nil {
		defer independent.Close()
	}
	if ctx == nil || ctx.Err() != nil || independent == nil || !filepath.IsAbs(request.CiphertextDirectory) || filepath.Clean(request.CiphertextDirectory) != request.CiphertextDirectory || !validRecoveryFingerprint(request.ExpectedFingerprint) {
		return result, nativeError(generated.ErrorCodeInputInvalid, "credential-recovery-request")
	}
	stopClose := context.AfterFunc(ctx, func() { _ = independent.Close() })
	defer stopClose()
	if _, parseErr := credentialref.ParseID(request.Name); parseErr != nil {
		return result, nativeError(generated.ErrorCodeInputInvalid, "credential-recovery-name")
	}
	keyDigest, keyIdentity, keyErr := inspectRecoveryHostKey(request.ExpectedUID)
	if keyErr != nil {
		return result, keyErr
	}
	directoryFD, openErr := unix.Open(request.CiphertextDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if openErr != nil {
		return result, nativeError(generated.ErrorCodePrerequisiteBlocked, "ciphertext-directory")
	}
	defer unix.Close(directoryFD)
	var directory unix.Stat_t
	if unix.Fstat(directoryFD, &directory) != nil || directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Uid != request.ExpectedUID || directory.Mode&0o777 != 0o700 {
		return result, nativeError(generated.ErrorCodeAuthorizationDenied, "ciphertext-directory")
	}
	fileFD, openErr := unix.Openat(directoryFD, request.Name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if openErr != nil {
		return result, nativeError(generated.ErrorCodeRecoveryRequired, "credential-recovery-draft")
	}
	file := os.NewFile(uintptr(fileFD), "credential-recovery-ciphertext")
	if file == nil {
		_ = unix.Close(fileFD)
		return result, nativeError(generated.ErrorCodeRecoveryRequired, "credential-recovery-draft")
	}
	defer file.Close()
	var initial unix.Stat_t
	if unix.Fstat(fileFD, &initial) != nil || !validRecoveryCiphertextStat(initial, request.ExpectedUID) {
		return result, nativeError(generated.ErrorCodeRecoveryRequired, "credential-recovery-draft")
	}
	ciphertext, readErr := io.ReadAll(io.LimitReader(file, 8193))
	if readErr != nil || len(ciphertext) < 16 || len(ciphertext) > 8192 || ctx.Err() != nil {
		return result, nativeError(generated.ErrorCodeRecoveryRequired, "credential-recovery-draft")
	}
	defer wipe(ciphertext)
	sum := sha256.Sum256(ciphertext)
	fingerprint := "sha256:" + hex.EncodeToString(sum[:])
	if fingerprint != request.ExpectedFingerprint {
		return result, nativeError(generated.ErrorCodeRecoveryRequired, "credential-recovery-fingerprint")
	}
	expectedLength, readErr := readBoundedPrivate(independent, expected[:], 8, 4096)
	if readErr != nil || ctx.Err() != nil {
		return result, nativeError(generated.ErrorCodeRecoveryRequired, "credential-recovery-custody")
	}
	sealedFD, memErr := unix.MemfdCreate("vsk-recovery-ciphertext", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if memErr != nil {
		return result, nativeError(generated.ErrorCodeDependencyUnavailable, "credential-recovery-buffer")
	}
	sealed := os.NewFile(uintptr(sealedFD), "sealed-recovery-ciphertext")
	if sealed == nil {
		_ = unix.Close(sealedFD)
		return result, nativeError(generated.ErrorCodeDependencyUnavailable, "credential-recovery-buffer")
	}
	defer sealed.Close()
	if _, writeErr := sealed.Write(ciphertext); writeErr != nil {
		return result, nativeError(generated.ErrorCodeDependencyUnavailable, "credential-recovery-buffer")
	}
	if _, sealErr := unix.FcntlInt(sealed.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); sealErr != nil {
		return result, nativeError(generated.ErrorCodeDependencyUnavailable, "credential-recovery-buffer")
	}
	if _, seekErr := sealed.Seek(0, io.SeekStart); seekErr != nil {
		return result, nativeError(generated.ErrorCodeDependencyUnavailable, "credential-recovery-buffer")
	}
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(deadline, credsCommandPath, "decrypt", "--name="+request.Name, "/proc/self/fd/3", "-")
	command.ExtraFiles = []*os.File{sealed}
	stdout, pipeErr := command.StdoutPipe()
	if pipeErr != nil {
		return result, nativeError(generated.ErrorCodeRecoveryRequired, "credential-recovery-decrypt")
	}
	defer stdout.Close()
	discard, discardErr := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if discardErr != nil {
		return result, nativeError(generated.ErrorCodeRecoveryRequired, "credential-recovery-decrypt")
	}
	defer discard.Close()
	command.Stderr = discard
	command.Env = []string{"LANG=C", "PATH=/usr/bin:/bin"}
	if command.Start() != nil {
		return result, nativeError(generated.ErrorCodeRecoveryRequired, "credential-recovery-decrypt")
	}
	outputLength, outputErr := readBoundedPrivate(stdout, output[:], 8, 4096)
	if outputErr != nil {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	if outputErr != nil || waitErr != nil || deadline.Err() != nil {
		return result, nativeError(generated.ErrorCodeRecoveryRequired, "credential-recovery-decrypt")
	}
	if subtle.ConstantTimeCompare(expected[:expectedLength], output[:outputLength]) != 1 {
		return result, nativeError(generated.ErrorCodeRecoveryRequired, "credential-recovery-custody-mismatch")
	}
	finalKeyDigest, finalKeyIdentity, keyErr := inspectRecoveryHostKey(request.ExpectedUID)
	if keyErr != nil || finalKeyDigest != keyDigest || finalKeyIdentity != keyIdentity {
		return result, nativeError(generated.ErrorCodeRecoveryRequired, "native-host-key-changed")
	}
	// Re-open through the original protected directory after decrypt to reject
	// replacement or mutation of the draft while the child was running.
	currentFD, openErr := unix.Openat(directoryFD, request.Name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if openErr != nil {
		return result, nativeError(generated.ErrorCodeRecoveryRequired, "credential-recovery-draft-changed")
	}
	current := os.NewFile(uintptr(currentFD), "credential-recovery-current")
	if current == nil {
		_ = unix.Close(currentFD)
		return result, nativeError(generated.ErrorCodeRecoveryRequired, "credential-recovery-draft-changed")
	}
	defer current.Close()
	var final unix.Stat_t
	if unix.Fstat(currentFD, &final) != nil || !validRecoveryCiphertextStat(final, request.ExpectedUID) || initial.Dev != final.Dev || initial.Ino != final.Ino || initial.Size != final.Size {
		return result, nativeError(generated.ErrorCodeRecoveryRequired, "credential-recovery-draft-changed")
	}
	again, readErr := io.ReadAll(io.LimitReader(current, 8193))
	if readErr != nil || !bytes.Equal(again, ciphertext) || ctx.Err() != nil {
		return result, nativeError(generated.ErrorCodeRecoveryRequired, "credential-recovery-draft-changed")
	}
	return VerifiedDraft{CiphertextFingerprint: fingerprint, HostKeyDigest: keyDigest}, nil
}

type recoveryHostKeyIdentity struct{ device, inode uint64 }

func inspectRecoveryHostKey(ownerUID uint32) (digest string, identity recoveryHostKeyIdentity, err error) {
	fd, openErr := unix.Open(hostKeyPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if openErr != nil {
		return "", identity, nativeError(generated.ErrorCodePrerequisiteBlocked, "native-host-key")
	}
	file := os.NewFile(uintptr(fd), "native-recovery-host-key")
	if file == nil {
		_ = unix.Close(fd)
		return "", identity, nativeError(generated.ErrorCodePrerequisiteBlocked, "native-host-key")
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 || stat.Size < 32 || stat.Size > 8192 {
		return "", identity, nativeError(generated.ErrorCodePrerequisiteBlocked, "native-host-key")
	}
	if stat.Uid != 0 && stat.Uid != ownerUID {
		return "", identity, nativeError(generated.ErrorCodeAuthorizationDenied, "native-host-key")
	}
	var key [8193]byte
	defer wipe(key[:])
	keyLength, readErr := readBoundedPrivate(file, key[:int(stat.Size)+1], int(stat.Size), int(stat.Size))
	if readErr != nil || keyLength != int(stat.Size) {
		return "", identity, nativeError(generated.ErrorCodePrerequisiteBlocked, "native-host-key")
	}
	sum := sha256.Sum256(key[:keyLength])
	return "sha256:" + hex.EncodeToString(sum[:]), recoveryHostKeyIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

// readBoundedPrivate writes directly into a caller-owned fixed buffer. The
// extra byte proves EOF at the exact maximum without allocating a private
// copy. The caller wipes the entire buffer on every exit.
func readBoundedPrivate(reader io.Reader, owned []byte, minimum, maximum int) (int, error) {
	if reader == nil || minimum < 0 || maximum < minimum || len(owned) != maximum+1 {
		return 0, io.ErrShortBuffer
	}
	count, emptyReads := 0, 0
	for {
		read, readErr := reader.Read(owned[count:])
		if read < 0 || read > len(owned)-count {
			return count, io.ErrUnexpectedEOF
		}
		count += read
		if count > maximum {
			return count, io.ErrShortBuffer
		}
		if readErr == io.EOF {
			if count < minimum {
				return count, io.ErrUnexpectedEOF
			}
			return count, nil
		}
		if readErr != nil {
			return count, readErr
		}
		if read == 0 {
			emptyReads++
			if emptyReads >= 100 {
				return count, io.ErrNoProgress
			}
		} else {
			emptyReads = 0
		}
	}
}

func validRecoveryCiphertextStat(stat unix.Stat_t, ownerUID uint32) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Uid == ownerUID && stat.Mode&0o777 == 0o600 && stat.Nlink == 1 && stat.Size >= 16 && stat.Size <= 8192
}

func validRecoveryFingerprint(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	for _, char := range value[7:] {
		if char < '0' || char > '9' && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}
