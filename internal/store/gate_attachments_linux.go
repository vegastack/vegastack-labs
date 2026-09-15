//go:build linux

package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/sys/unix"
)

const gateAttachmentMaxBytes = 8 << 20

var gateAttachmentDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type GateAttachmentStore struct {
	root string
	uid uint32
}

func NewGateAttachmentStore(root string, expectedUID uint32) (*GateAttachmentStore, error) {
	store := &GateAttachmentStore{root: root, uid: expectedUID}
	fd, err := store.openRoot()
	if err != nil { return nil, err }
	if err := unix.Close(fd); err != nil { return nil, newStoreError(generated.ErrorCodeIntegrityFailure, "gate-attachment-directory", false, nil) }
	return store, nil
}

func (store *GateAttachmentStore) openRoot() (int, error) {
	if store == nil || !filepath.IsAbs(store.root) || filepath.Clean(store.root) != store.root {
		return -1, newStoreError(generated.ErrorCodeInputInvalid, "gate-attachment-directory", false, nil)
	}
	fd, err := unix.Open(store.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil { return -1, newStoreError(generated.ErrorCodeIntegrityFailure, "gate-attachment-directory", false, err) }
	var stat unix.Stat_t
	var filesystem unix.Statfs_t
	if unix.Fstat(fd, &stat) != nil || unix.Fstatfs(fd, &filesystem) != nil || stat.Uid != store.uid || stat.Mode&0o777 != 0o700 || !isLocalFilesystemType(uint64(filesystem.Type)) {
		_ = unix.Close(fd)
		return -1, newStoreError(generated.ErrorCodeIntegrityFailure, "gate-attachment-directory", false, nil)
	}
	return fd, nil
}

func gateAttachmentName(digest string) (string, error) {
	if !gateAttachmentDigestPattern.MatchString(digest) { return "", newStoreError(generated.ErrorCodeInputInvalid, "gate-attachment-digest", false, nil) }
	return digest[len("sha256:"):], nil
}

func (store *GateAttachmentStore) Put(ctx context.Context, digest string, data []byte) error {
	if err := ctx.Err(); err != nil { return newStoreError(generated.ErrorCodeInterrupted, "gate-attachment", false, err) }
	name, err := gateAttachmentName(digest)
	if err != nil || len(data) == 0 || len(data) > gateAttachmentMaxBytes || gateDigest(data) != digest {
		return newStoreError(generated.ErrorCodeInputInvalid, "gate-attachment", false, err)
	}
	root, err := store.openRoot()
	if err != nil { return err }
	defer unix.Close(root)
	if existing, err := store.readAt(root, name); err == nil {
		if bytes.Equal(existing, data) { return nil }
		return newStoreError(generated.ErrorCodeIntegrityFailure, "gate-attachment", false, nil)
	} else if !errors.Is(err, unix.ENOENT) {
		return newStoreError(generated.ErrorCodeIntegrityFailure, "gate-attachment", false, err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil { return newStoreError(generated.ErrorCodeIntegrityFailure, "gate-attachment", false, err) }
	temporary := ".pending-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(root, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil { return newStoreError(generated.ErrorCodeIntegrityFailure, "gate-attachment", false, err) }
	published := false
	defer func() { if !published { _ = unix.Unlinkat(root, temporary, 0) } }()
	file := os.NewFile(uintptr(fd), temporary)
	if file == nil { _ = unix.Close(fd); return newStoreError(generated.ErrorCodeIntegrityFailure, "gate-attachment", false, nil) }
	written, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(data) { return newStoreError(generated.ErrorCodeIntegrityFailure, "gate-attachment", false, nil) }
	if err := ctx.Err(); err != nil { return newStoreError(generated.ErrorCodeInterrupted, "gate-attachment", false, err) }
	if err := unix.Renameat2(root, temporary, root, name, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			existing, readErr := store.readAt(root, name)
			if readErr == nil && bytes.Equal(existing, data) { return nil }
		}
		return newStoreError(generated.ErrorCodeIntegrityFailure, "gate-attachment", false, err)
	}
	published = true
	if err := unix.Fsync(root); err != nil { return newStoreError(generated.ErrorCodeIntegrityFailure, "gate-attachment", false, err) }
	return nil
}

func (store *GateAttachmentStore) Get(ctx context.Context, digest string) ([]byte, error) {
	if err := ctx.Err(); err != nil { return nil, newStoreError(generated.ErrorCodeInterrupted, "gate-attachment", false, err) }
	name, err := gateAttachmentName(digest)
	if err != nil { return nil, err }
	root, err := store.openRoot()
	if err != nil { return nil, err }
	defer unix.Close(root)
	raw, err := store.readAt(root, name)
	if err != nil || gateDigest(raw) != digest { return nil, newStoreError(generated.ErrorCodeIntegrityFailure, "gate-attachment", false, err) }
	return raw, nil
}

func (store *GateAttachmentStore) readAt(root int, name string) ([]byte, error) {
	fd, err := unix.Openat(root, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil { return nil, err }
	file := os.NewFile(uintptr(fd), name)
	if file == nil { _ = unix.Close(fd); return nil, unix.EIO }
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != store.uid || stat.Mode&0o777 != 0o600 || stat.Size < 1 || stat.Size > gateAttachmentMaxBytes {
		return nil, unix.EIO
	}
	raw, err := io.ReadAll(io.LimitReader(file, gateAttachmentMaxBytes+1))
	if err != nil || len(raw) > gateAttachmentMaxBytes { return nil, unix.EIO }
	return raw, nil
}
