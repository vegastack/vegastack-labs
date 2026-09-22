//go:build linux || darwin

package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const systemRecoveryDirectory = "/etc/vsk-labs/recovery"
const systemSignedWitnessName = "signed-witness.json"
const systemEnvelopeName = "custody-envelope.json"
const maxEnvelopeArtifactBytes = 8192

// InstalledPackage is public signed witness evidence and an opaque encrypted
// envelope. It contains no plaintext recovery material or private key.
type InstalledPackage struct {
	Pin      PinnedWitness
	Witness  SignedWitness
	Envelope ProtectedEnvelope
}

// LoadSystemRecoveryPackage uses only the fixed protected OS directory and
// administrator root. A root-running controller cannot claim independence.
func LoadSystemRecoveryPackage(ctx context.Context, expected WitnessBinding) (InstalledPackage, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() == 0 || !validBinding(expected) {
		return InstalledPackage{}, ErrWitnessUnavailable
	}
	pin, err := LoadSystemWitnessManifest(expected)
	if err != nil {
		return InstalledPackage{}, ErrWitnessUnavailable
	}
	files, err := readProtectedPackageFiles(systemRecoveryDirectory, 0, nil)
	if err != nil || ctx.Err() != nil {
		return InstalledPackage{}, ErrWitnessUnavailable
	}
	signed, err := DecodeSignedWitness(files[0])
	if err != nil || VerifySignedWitness(ctx, pin, expected, signed, time.Now().UTC()) != nil {
		return InstalledPackage{}, ErrWitnessUnavailable
	}
	envelope, err := decodeProtectedEnvelope(files[1], pin, expected)
	if err != nil {
		return InstalledPackage{}, ErrWitnessUnavailable
	}
	// If an administrator rotates the independently installed manifest while
	// the package is read, this attempt must begin again with the new pin.
	current, err := LoadSystemWitnessManifest(expected)
	if err != nil || current.ManifestDigest != pin.ManifestDigest || ctx.Err() != nil {
		return InstalledPackage{}, ErrWitnessUnavailable
	}
	return InstalledPackage{Pin: pin, Witness: signed, Envelope: envelope}, nil
}

func decodeProtectedEnvelope(raw []byte, pin PinnedWitness, expected WitnessBinding) (ProtectedEnvelope, error) {
	var envelope ProtectedEnvelope
	if len(raw) == 0 || len(raw) > maxEnvelopeArtifactBytes || json.Unmarshal(raw, &envelope) != nil {
		return ProtectedEnvelope{}, ErrWitnessUnavailable
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ProtectedEnvelope{}, ErrWitnessUnavailable
	}
	digest, _, _, err := transportBinding(pin, expected)
	if err != nil || envelope.Version != 1 || envelope.RecipientKeyID != pin.RecipientKeyID || envelope.BindingDigest != digest || envelope.ReceiptID != expected.ReceiptID || len(envelope.EphemeralPublicKey) != 32 || len(envelope.Nonce) != 12 || len(envelope.Ciphertext) < 24 || len(envelope.Ciphertext) > 4112 {
		return ProtectedEnvelope{}, ErrWitnessUnavailable
	}
	return envelope, nil
}

// readProtectedPackageFiles pins both opened inodes, then confirms their
// directory entries still name those inodes after the bounded reads. afterOpen
// is a package-private race-test seam; production always passes nil.
func readProtectedPackageFiles(directory string, uid uint32, afterOpen func()) ([2][]byte, error) {
	var empty [2][]byte
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return empty, ErrWitnessUnavailable
	}
	dirFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return empty, ErrWitnessUnavailable
	}
	defer unix.Close(dirFD)
	var directoryStat unix.Stat_t
	if unix.Fstat(dirFD, &directoryStat) != nil || directoryStat.Mode&unix.S_IFMT != unix.S_IFDIR || directoryStat.Uid != uid || directoryStat.Mode&0o022 != 0 {
		return empty, ErrWitnessUnavailable
	}
	names := [2]string{systemSignedWitnessName, systemEnvelopeName}
	limits := [2]int{maxSignedWitnessArtifactBytes, maxEnvelopeArtifactBytes}
	var files [2]*os.File
	var stats [2]unix.Stat_t
	defer func() {
		for _, file := range files {
			if file != nil {
				_ = file.Close()
			}
		}
	}()
	for i, name := range names {
		fd, openErr := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return empty, ErrWitnessUnavailable
		}
		files[i] = os.NewFile(uintptr(fd), "protected-recovery-artifact")
		if files[i] == nil {
			_ = unix.Close(fd)
			return empty, ErrWitnessUnavailable
		}
		if unix.Fstat(fd, &stats[i]) != nil || !validProtectedPackageStat(stats[i], uid, limits[i]) {
			return empty, ErrWitnessUnavailable
		}
	}
	if afterOpen != nil {
		afterOpen()
	}
	var content [2][]byte
	for i, file := range files {
		data, readErr := io.ReadAll(io.LimitReader(file, int64(limits[i])+1))
		if readErr != nil || len(data) != int(stats[i].Size) {
			return empty, ErrWitnessUnavailable
		}
		content[i] = data
	}
	for i, name := range names {
		var opened, current unix.Stat_t
		if unix.Fstat(int(files[i].Fd()), &opened) != nil || unix.Fstatat(dirFD, name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameProtectedPackageStat(stats[i], opened) || !sameProtectedPackageStat(stats[i], current) {
			return empty, ErrWitnessUnavailable
		}
	}
	currentFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return empty, ErrWitnessUnavailable
	}
	defer unix.Close(currentFD)
	var currentDir unix.Stat_t
	if unix.Fstat(currentFD, &currentDir) != nil || !sameProtectedPackageStat(directoryStat, currentDir) {
		return empty, ErrWitnessUnavailable
	}
	return content, nil
}

func validProtectedPackageStat(stat unix.Stat_t, uid uint32, max int) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Uid == uid && stat.Mode&0o022 == 0 && stat.Nlink == 1 && stat.Size >= 1 && stat.Size <= int64(max)
}

func sameProtectedPackageStat(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode && left.Uid == right.Uid && left.Gid == right.Gid && left.Nlink == right.Nlink && left.Size == right.Size && left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func protectedEnvelopeDigest(envelope ProtectedEnvelope) string {
	encoded, _ := json.Marshal(envelope)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}
