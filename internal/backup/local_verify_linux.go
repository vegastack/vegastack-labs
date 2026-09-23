//go:build linux

package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

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
	observed, err := hashPointObjects(ctx, server, manifest.ExpectedObjects)
	if err != nil {
		return LocalInventoryProof{}, invalid
	}
	return VerifyCustodyInventory(manifest, manifestDigest, observed)
}

// VerifyCustodyInventory validates the authenticated typed inventory returned
// by the custody child. The controller never opens a repository object.
func VerifyCustodyInventory(manifest CreationManifest, manifestDigest string, observed []ExpectedObject) (LocalInventoryProof, error) {
	invalid := errors.New("local backup inventory mismatch")
	_, canonicalDigest, err := CanonicalCreationManifest(manifest)
	if err != nil || manifestDigest != canonicalDigest || len(observed) != len(manifest.ExpectedObjects) || ExpectedInventoryDigest(observed) != manifest.InventoryDigest {
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
	return LocalInventoryProof{PointID: manifest.PointID, SnapshotID: manifest.SnapshotID, ManifestDigest: manifestDigest,
		InventoryDigest: manifest.InventoryDigest, ObservedDigest: ExpectedInventoryDigest(observed), RecoveryEpoch: manifest.RecoveryEpoch}, nil
}

// hashPointObjects reads every object committed by this point's canonical
// manifest. Later backup points may add immutable objects to the repository;
// those cannot invalidate an earlier retained point's own inventory.
func hashPointObjects(ctx context.Context, server *RESTServer, expected []ExpectedObject) ([]ExpectedObject, error) {
	objects := make([]ExpectedObject, 0, len(expected))
	for _, item := range expected {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		request := objectRequest{objectType: item.Type, name: item.Name, retained: true}
		if item.Type == "config" && item.Name == "config" {
			request.isConfig = true
		} else if _, allowed := retainedObjectTypes[item.Type]; !allowed || !validObjectName(item.Name) {
			return nil, errors.New("invalid retained object reference")
		}
		object, err := hashLeasedObject(server, request)
		if err != nil {
			return nil, err
		}
		objects = append(objects, object)
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
