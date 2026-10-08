//go:build linux

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"

	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

type loadedDiscoveryKeyReader struct{ ownerUID uint32 }

func newPreloadedDiscoveryKeyReader(ownerUID uint32) preloadedDiscoveryKeyReader {
	return loadedDiscoveryKeyReader{ownerUID: ownerUID}
}

// Borrow checks only the protected material for an already authorized discovery
// target. The caller owns current target/profile authorization and closes Value.
// This reader never activates or resolves a general CredentialReference.
func (r loadedDiscoveryKeyReader) Borrow(ctx context.Context, target hostdiscovery.Target) (*credentialref.Value, error) {
	blocked := func() (*credentialref.Value, error) {
		return nil, hostdiscovery.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	t := target.Binding
	if ctx == nil || ctx.Err() != nil || t.CredentialMode == nil || *t.CredentialMode != "preloaded-discovery" || t.CredentialPublicKeyDigest == nil || hostdiscovery.ValidateTarget(t) != nil {
		return blocked()
	}
	name := nativecredential.LoadedNameForVersion(hostdiscovery.Consumer, t.CredentialReferenceID, t.MaterialVersion)
	directoryPath := os.Getenv("CREDENTIALS_DIRECTORY")
	if name == "" || !filepath.IsAbs(directoryPath) || filepath.Clean(directoryPath) != directoryPath {
		return blocked()
	}
	fd, err := unix.Open(directoryPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return blocked()
	}
	directory := os.NewFile(uintptr(fd), "discovery-credentials")
	defer directory.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != r.ownerUID || stat.Mode&0077 != 0 {
		return blocked()
	}
	raw, err := nativecredential.ReadLoadedBytes(ctx, directory, name, r.ownerUID)
	if err != nil {
		return blocked()
	}
	defer zeroCredential(raw)
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return blocked()
	}
	sum := sha256.Sum256(signer.PublicKey().Marshal())
	if "sha256:"+hex.EncodeToString(sum[:]) != *t.CredentialPublicKeyDigest || ctx.Err() != nil {
		return blocked()
	}
	value, err := credentialref.NewValue(raw)
	if err != nil {
		return blocked()
	}
	return value, nil
}
