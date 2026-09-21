//go:build linux || darwin

package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const systemReceiptDirectory = "/var/lib/vsk-labs/recovery-witness-receipts"
const receiptDomain = "vegastack-labs.dev/recovery-witness-receipt/v1\x00"

// NewSystemReceiptStore uses an OS-protected directory on the clean
// replacement host, outside the restored SQLite database. Provisioning the
// directory and its separate ownership is an administrator prerequisite.
func NewSystemReceiptStore() ReceiptStore {
	return fileReceiptStore{directory: systemReceiptDirectory, expectedUID: uint32(os.Geteuid())}
}

type fileReceiptStore struct {
	directory   string
	expectedUID uint32
}

// Consume durably claims each receipt ID and challenge ID independently. A
// partial or interrupted claim is never undone; conservative burn-on-failure
// prevents a new pair from reusing either successful attempt's identity.
func (store fileReceiptStore) Consume(ctx context.Context, receiptID, challengeID string) error {
	if ctx == nil || ctx.Err() != nil || !validWitnessToken(receiptID) || !validWitnessToken(challengeID) || !filepath.IsAbs(store.directory) || filepath.Clean(store.directory) != store.directory {
		return ErrWitnessUnavailable
	}
	directoryFD, err := unix.Open(store.directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrWitnessUnavailable
	}
	defer unix.Close(directoryFD)
	var stat unix.Stat_t
	if unix.Fstat(directoryFD, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != store.expectedUID || stat.Mode&0o777 != 0o700 {
		return ErrWitnessUnavailable
	}
	if claimReceiptMarker(directoryFD, "receipt", receiptID) != nil ||
		claimReceiptMarker(directoryFD, "challenge", challengeID) != nil {
		return ErrWitnessUnavailable
	}
	if unix.Fsync(directoryFD) != nil || ctx.Err() != nil {
		return ErrWitnessUnavailable
	}
	return nil
}

func claimReceiptMarker(directoryFD int, kind, id string) error {
	sum := sha256.Sum256([]byte(receiptDomain + kind + "\x00" + id))
	name := hex.EncodeToString(sum[:])
	fd, err := unix.Openat(directoryFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return ErrWitnessUnavailable
	}
	if unix.Fsync(fd) != nil {
		_ = unix.Close(fd)
		return ErrWitnessUnavailable
	}
	if unix.Close(fd) != nil {
		return ErrWitnessUnavailable
	}
	return nil
}
