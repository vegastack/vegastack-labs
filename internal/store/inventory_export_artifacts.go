//go:build linux

package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
	"golang.org/x/sys/unix"
)

const (
	exportArtifactDirectory = "artifacts"
	exportCurrentFile       = "current.json"
)

var exportArtifactIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type InventoryExportArtifactConfig struct {
	Root        string
	ExpectedUID uint32
}

type inventoryExportArtifactStore struct {
	config InventoryExportArtifactConfig
	fault  func(string) error
}

func NewInventoryExportArtifactStore(config InventoryExportArtifactConfig) (stateexport.ArtifactStore, error) {
	store := &inventoryExportArtifactStore{config: config}
	root, err := store.openRoot(context.Background())
	if err != nil {
		return nil, err
	}
	defer unix.Close(root)
	if err := unix.Mkdirat(root, exportArtifactDirectory, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, artifactError("INTEGRITY_FAILURE")
	}
	artifacts, err := store.openArtifactsAt(root)
	if err != nil {
		return nil, err
	}
	if unix.Close(artifacts) != nil || unix.Fsync(root) != nil {
		return nil, artifactError("INTEGRITY_FAILURE")
	}
	return store, nil
}

func (store *inventoryExportArtifactStore) InspectCurrent(ctx context.Context) (*stateexport.CurrentPointer, error) {
	root, err := store.openRoot(ctx)
	if err != nil {
		return nil, err
	}
	defer unix.Close(root)
	raw, err := store.readProtectedAt(root, exportCurrentFile, stateexport.MaxArtifactBytes)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, artifactError("INTEGRITY_FAILURE")
	}
	pointer, err := stateexport.DecodePointer(raw)
	if err != nil {
		return nil, artifactError("INTEGRITY_FAILURE")
	}
	artifacts, err := store.openArtifactsAt(root)
	if err != nil {
		return nil, err
	}
	defer unix.Close(artifacts)
	artifact, err := store.readProtectedAt(artifacts, artifactName(pointer.ArtifactID), stateexport.MaxArtifactBytes)
	if err != nil || digestBytes(artifact) != pointer.ArtifactID {
		return nil, artifactError("INTEGRITY_FAILURE")
	}
	document, err := stateexport.DecodeSignedExport(artifact)
	if err != nil || document.ContentDigest != pointer.ContentDigest {
		return nil, artifactError("INTEGRITY_FAILURE")
	}
	return &pointer, nil
}

func (store *inventoryExportArtifactStore) ReadArtifact(ctx context.Context, artifactID string) ([]byte, error) {
	if !exportArtifactIDPattern.MatchString(artifactID) {
		return nil, artifactError("INPUT_INVALID")
	}
	root, err := store.openRoot(ctx)
	if err != nil {
		return nil, err
	}
	defer unix.Close(root)
	artifacts, err := store.openArtifactsAt(root)
	if err != nil {
		return nil, err
	}
	defer unix.Close(artifacts)
	raw, err := store.readProtectedAt(artifacts, artifactName(artifactID), stateexport.MaxArtifactBytes)
	if err != nil || digestBytes(raw) != artifactID {
		return nil, artifactError("INTEGRITY_FAILURE")
	}
	return raw, nil
}

func (store *inventoryExportArtifactStore) Publish(ctx context.Context, request stateexport.PublishRequest) (stateexport.Publication, error) {
	if err := ctx.Err(); err != nil {
		return stateexport.Publication{}, artifactError("INTERRUPTED")
	}
	if len(request.Bytes) == 0 || len(request.Bytes) > stateexport.MaxArtifactBytes || !exportArtifactIDPattern.MatchString(request.ArtifactID) ||
		!exportArtifactIDPattern.MatchString(request.ContentDigest) || digestBytes(request.Bytes) != request.ArtifactID {
		return stateexport.Publication{}, artifactError("INPUT_INVALID")
	}
	document, err := stateexport.DecodeSignedExport(request.Bytes)
	if err != nil || document.ContentDigest != request.ContentDigest {
		return stateexport.Publication{}, artifactError("INPUT_INVALID")
	}
	previous, err := store.InspectCurrent(ctx)
	if err != nil {
		return stateexport.Publication{}, err
	}
	root, err := store.openRoot(ctx)
	if err != nil {
		return stateexport.Publication{}, err
	}
	defer unix.Close(root)
	artifacts, err := store.openArtifactsAt(root)
	if err != nil {
		return stateexport.Publication{}, err
	}
	defer unix.Close(artifacts)
	created, err := store.publishArtifact(ctx, artifacts, request)
	if err != nil {
		return stateexport.Publication{}, err
	}
	current := stateexport.CurrentPointer{Schema: stateexport.PointerSchema, SchemaVersion: stateexport.SchemaVersion, ExportKind: stateexport.ExportKind, ArtifactID: request.ArtifactID, ContentDigest: request.ContentDigest}
	pointerBytes, err := stateexport.CanonicalPointer(current)
	if err != nil {
		return stateexport.Publication{}, artifactError("INTEGRITY_FAILURE")
	}
	if err := store.replacePointer(ctx, root, pointerBytes, true); err != nil {
		_ = store.restorePointerBytes(context.Background(), root, previous)
		return stateexport.Publication{}, err
	}
	return stateexport.Publication{Current: current, Previous: clonePointer(previous), Created: created}, nil
}

func (store *inventoryExportArtifactStore) RestoreCurrent(ctx context.Context, expected stateexport.CurrentPointer, previous *stateexport.CurrentPointer) error {
	current, err := store.InspectCurrent(ctx)
	if err != nil {
		return err
	}
	if current == nil || *current != expected {
		return artifactError("STATE_CONFLICT")
	}
	if previous != nil {
		if _, err := store.ReadArtifact(ctx, previous.ArtifactID); err != nil {
			return err
		}
	}
	root, err := store.openRoot(ctx)
	if err != nil {
		return err
	}
	defer unix.Close(root)
	return store.restorePointerBytes(ctx, root, previous)
}

func (store *inventoryExportArtifactStore) publishArtifact(ctx context.Context, directory int, request stateexport.PublishRequest) (bool, error) {
	name := artifactName(request.ArtifactID)
	if existing, err := store.readProtectedAt(directory, name, stateexport.MaxArtifactBytes); err == nil {
		if bytes.Equal(existing, request.Bytes) {
			return false, nil
		}
		return false, artifactError("INTEGRITY_FAILURE")
	} else if !errors.Is(err, unix.ENOENT) {
		return false, artifactError("INTEGRITY_FAILURE")
	}
	if err := store.inject("create-temp"); err != nil {
		return false, err
	}
	tempName, descriptor, err := createTempAt(directory, ".artifact-")
	if err != nil {
		return false, artifactError("INTEGRITY_FAILURE")
	}
	keepTemp := true
	defer func() {
		if keepTemp {
			_ = unix.Unlinkat(directory, tempName, 0)
		}
	}()
	file := os.NewFile(uintptr(descriptor), "inventory-export-artifact")
	if file == nil {
		_ = unix.Close(descriptor)
		return false, artifactError("INTEGRITY_FAILURE")
	}
	if err := store.inject("write"); err != nil {
		_ = file.Close()
		return false, err
	}
	written, writeErr := file.Write(request.Bytes)
	if writeErr != nil || written != len(request.Bytes) || store.inject("file-sync") != nil || file.Sync() != nil || file.Close() != nil {
		return false, artifactError("INTEGRITY_FAILURE")
	}
	if err := store.inject("reopen"); err != nil {
		return false, err
	}
	reopened, err := store.readProtectedAt(directory, tempName, stateexport.MaxArtifactBytes)
	if err != nil || !bytes.Equal(reopened, request.Bytes) {
		return false, artifactError("INTEGRITY_FAILURE")
	}
	if err := ctx.Err(); err != nil {
		return false, artifactError("INTERRUPTED")
	}
	if err := store.inject("artifact-rename"); err != nil {
		return false, err
	}
	if err := unix.Renameat2(directory, tempName, directory, name, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			existing, readErr := store.readProtectedAt(directory, name, stateexport.MaxArtifactBytes)
			if readErr == nil && bytes.Equal(existing, request.Bytes) {
				return false, nil
			}
		}
		return false, artifactError("INTEGRITY_FAILURE")
	}
	keepTemp = false
	if err := store.inject("directory-sync"); err != nil || unix.Fsync(directory) != nil {
		return false, artifactError("INTEGRITY_FAILURE")
	}
	return true, nil
}

func (store *inventoryExportArtifactStore) replacePointer(ctx context.Context, root int, body []byte, inject bool) error {
	if err := ctx.Err(); err != nil {
		return artifactError("INTERRUPTED")
	}
	tempName, descriptor, err := createTempAt(root, ".current-")
	if err != nil {
		return artifactError("INTEGRITY_FAILURE")
	}
	defer unix.Unlinkat(root, tempName, 0)
	file := os.NewFile(uintptr(descriptor), "inventory-export-current")
	if file == nil {
		_ = unix.Close(descriptor)
		return artifactError("INTEGRITY_FAILURE")
	}
	written, writeErr := file.Write(body)
	if writeErr != nil || written != len(body) || file.Sync() != nil || file.Close() != nil {
		return artifactError("INTEGRITY_FAILURE")
	}
	if _, err := store.readProtectedAt(root, tempName, stateexport.MaxArtifactBytes); err != nil {
		return artifactError("INTEGRITY_FAILURE")
	}
	if inject {
		if err := store.inject("pointer-rename"); err != nil {
			return err
		}
	}
	if err := unix.Renameat(root, tempName, root, exportCurrentFile); err != nil {
		return artifactError("INTEGRITY_FAILURE")
	}
	if inject {
		if err := store.inject("pointer-directory-sync"); err != nil {
			return err
		}
	}
	if err := unix.Fsync(root); err != nil {
		return artifactError("INTEGRITY_FAILURE")
	}
	return nil
}

func (store *inventoryExportArtifactStore) restorePointerBytes(ctx context.Context, root int, previous *stateexport.CurrentPointer) error {
	if previous == nil {
		if err := unix.Unlinkat(root, exportCurrentFile, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return artifactError("INTEGRITY_FAILURE")
		}
		if unix.Fsync(root) != nil {
			return artifactError("INTEGRITY_FAILURE")
		}
		return nil
	}
	body, err := stateexport.CanonicalPointer(*previous)
	if err != nil {
		return artifactError("INTEGRITY_FAILURE")
	}
	return store.replacePointer(ctx, root, body, false)
}

func (store *inventoryExportArtifactStore) openRoot(ctx context.Context) (int, error) {
	if store == nil || store.config.Root == "" || len(store.config.Root) > 4096 || strings.ContainsRune(store.config.Root, 0) ||
		!filepath.IsAbs(store.config.Root) || filepath.Clean(store.config.Root) != store.config.Root || store.config.Root == string(filepath.Separator) {
		return -1, artifactError("INPUT_INVALID")
	}
	if err := ctx.Err(); err != nil {
		return -1, artifactError("INTERRUPTED")
	}
	descriptor, err := unix.Openat2(unix.AT_FDCWD, store.config.Root, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS})
	if err != nil || validateExportDirectory(descriptor, store.config.ExpectedUID) != nil {
		if descriptor >= 0 {
			_ = unix.Close(descriptor)
		}
		return -1, artifactError("INTEGRITY_FAILURE")
	}
	return descriptor, nil
}

func (store *inventoryExportArtifactStore) openArtifactsAt(root int) (int, error) {
	descriptor, err := unix.Openat(root, exportArtifactDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil || validateExportDirectory(descriptor, store.config.ExpectedUID) != nil {
		if descriptor >= 0 {
			_ = unix.Close(descriptor)
		}
		return -1, artifactError("INTEGRITY_FAILURE")
	}
	return descriptor, nil
}

func validateExportDirectory(descriptor int, uid uint32) error {
	if descriptor < 0 {
		return errors.New("invalid descriptor")
	}
	var stat unix.Stat_t
	var filesystem unix.Statfs_t
	if unix.Fstat(descriptor, &stat) != nil || unix.Fstatfs(descriptor, &filesystem) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o777 != 0o700 || stat.Uid != uid || stat.Nlink < 1 || !isLocalFilesystemType(uint64(filesystem.Type)) {
		return errors.New("unsafe directory")
	}
	return nil
}

func (store *inventoryExportArtifactStore) readProtectedAt(directory int, name string, limit int64) ([]byte, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
		return nil, errors.New("unsafe name")
	}
	descriptor, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), "inventory-export-file")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("descriptor unavailable")
	}
	defer file.Close()
	var before unix.Stat_t
	if unix.Fstat(descriptor, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0o777 != 0o600 || before.Uid != store.config.ExpectedUID || before.Nlink != 1 || before.Size <= 0 || before.Size > limit {
		return nil, errors.New("unsafe file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) != before.Size {
		return nil, errors.New("file changed")
	}
	var after unix.Stat_t
	if unix.Fstat(descriptor, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Nlink != after.Nlink {
		return nil, errors.New("file identity changed")
	}
	return raw, nil
}

func createTempAt(directory int, prefix string) (string, int, error) {
	var entropy [12]byte
	if _, err := io.ReadFull(rand.Reader, entropy[:]); err != nil {
		return "", -1, err
	}
	name := prefix + hex.EncodeToString(entropy[:])
	descriptor, err := unix.Openat(directory, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	return name, descriptor, err
}

func artifactName(artifactID string) string {
	if !exportArtifactIDPattern.MatchString(artifactID) {
		return ""
	}
	return "sha256-" + strings.TrimPrefix(artifactID, "sha256:") + ".json"
}

func digestBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func clonePointer(pointer *stateexport.CurrentPointer) *stateexport.CurrentPointer {
	if pointer == nil {
		return nil
	}
	copy := *pointer
	return &copy
}

func (store *inventoryExportArtifactStore) inject(stage string) error {
	if store.fault != nil {
		if err := store.fault(stage); err != nil {
			return artifactError("INTEGRITY_FAILURE")
		}
	}
	return nil
}

func artifactError(code string) error {
	return failure.New(code, "inventory-export-artifacts", false)
}

var _ stateexport.ArtifactStore = (*inventoryExportArtifactStore)(nil)
