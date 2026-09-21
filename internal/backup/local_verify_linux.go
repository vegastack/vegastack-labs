//go:build linux

package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sort"

	"golang.org/x/sys/unix"
)

// LocalInventoryProof establishes that the current, read-leased repository
// contains exactly the immutable objects in one canonical pending manifest.
// Metadata and a restic full-read must be checked separately before this is a
// recovery qualification; this proof alone never advances last-good.
type LocalInventoryProof struct {
	PointID         string
	SnapshotID      string
	ManifestDigest  string
	InventoryDigest string
	ObservedDigest  string
	RecoveryEpoch   int64
}

func VerifyLocalInventory(ctx context.Context, manifest CreationManifest, manifestDigest string, server *RESTServer) (LocalInventoryProof, error) {
	invalid := errors.New("local backup inventory mismatch")
	if server == nil || !server.readOnly || server.readVerifier == nil ||
		manifest.PointID != server.readLease.PointID || manifest.RepositoryID != server.repositoryID ||
		manifest.RecoveryEpoch != server.readLease.RecoveryEpoch {
		return LocalInventoryProof{}, invalid
	}
	_, canonicalDigest, err := CanonicalCreationManifest(manifest)
	if err != nil || manifestDigest != canonicalDigest {
		return LocalInventoryProof{}, invalid
	}
	if err := server.readVerifier.VerifyReadLease(server.readLease, server.clock()); err != nil || !server.clock().Before(server.readLease.MaximumExpiresAt) {
		return LocalInventoryProof{}, invalid
	}
	observed, err := enumerateReadLeasedObjects(ctx, server)
	if err != nil || len(observed) != len(manifest.ExpectedObjects) || ExpectedInventoryDigest(observed) != manifest.InventoryDigest {
		return LocalInventoryProof{}, invalid
	}
	// The digest is canonical, but compare each record too, preventing any
	// parser/canonicalization discrepancy from qualifying an altered object.
	byKey := make(map[string]ExpectedObject, len(observed))
	for _, object := range observed {
		byKey[object.Type+"/"+object.Name] = object
	}
	for _, expected := range manifest.ExpectedObjects {
		if byKey[expected.Type+"/"+expected.Name] != expected {
			return LocalInventoryProof{}, invalid
		}
	}
	if err := server.readVerifier.VerifyReadLease(server.readLease, server.clock()); err != nil || !server.clock().Before(server.readLease.MaximumExpiresAt) {
		return LocalInventoryProof{}, invalid
	}
	return LocalInventoryProof{PointID: manifest.PointID, SnapshotID: manifest.SnapshotID, ManifestDigest: manifestDigest,
		InventoryDigest: manifest.InventoryDigest, ObservedDigest: ExpectedInventoryDigest(observed), RecoveryEpoch: manifest.RecoveryEpoch}, nil
}

func enumerateReadLeasedObjects(ctx context.Context, server *RESTServer) ([]ExpectedObject, error) {
	var objects []ExpectedObject
	for _, objectType := range []string{"config", "keys", "data", "index", "snapshots"} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if objectType == "config" {
			object, err := hashLeasedObject(server, objectRequest{objectType: "config", name: "config", isConfig: true, retained: true})
			if err != nil {
				return nil, err
			}
			objects = append(objects, object)
			continue
		}
		descriptor, err := server.openTypeDir(objectType, false)
		if err != nil {
			return nil, err
		}
		directory := os.NewFile(uintptr(descriptor), objectType)
		if directory == nil {
			_ = unix.Close(descriptor)
			return nil, errors.New("inventory directory unavailable")
		}
		names, err := directory.Readdirnames(-1)
		closeErr := directory.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		sort.Strings(names)
		for _, name := range names {
			if !validObjectName(name) {
				return nil, errors.New("invalid retained object name")
			}
			object, err := hashLeasedObject(server, objectRequest{objectType: objectType, name: name, retained: true})
			if err != nil {
				return nil, err
			}
			objects = append(objects, object)
		}
	}
	return objects, nil
}

func hashLeasedObject(server *RESTServer, request objectRequest) (ExpectedObject, error) {
	if err := server.readVerifier.VerifyReadLease(server.readLease, server.clock()); err != nil || !server.clock().Before(server.readLease.MaximumExpiresAt) {
		return ExpectedObject{}, errors.New("read lease stale")
	}
	descriptor, err := server.openObject(request, false)
	if err != nil {
		return ExpectedObject{}, err
	}
	file := os.NewFile(uintptr(descriptor), request.name)
	if file == nil {
		_ = unix.Close(descriptor)
		return ExpectedObject{}, errors.New("inventory object unavailable")
	}
	defer file.Close()
	hasher := sha256.New()
	bytes, err := io.Copy(hasher, file)
	if err != nil {
		return ExpectedObject{}, err
	}
	return ExpectedObject{Type: request.objectType, Name: request.name, Bytes: bytes, Digest: "sha256:" + hex.EncodeToString(hasher.Sum(nil))}, nil
}
