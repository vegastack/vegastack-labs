//go:build linux

package nativecredential

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/sys/unix"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type ReferenceInspector interface {
	GetReference(context.Context, string) (generated.CredentialReference, error)
}

// LoadedCredential is a server-owned observation of the service manager's
// restarted, loaded version. An absent observer does not grant authority.
type LoadedCredential struct {
	Name, MaterialVersion, CiphertextFingerprint string
	RestartObserved                              bool
}
type LoadedObserver interface {
	ObserveLoaded(context.Context, credentialref.StepBinding) (LoadedCredential, error)
}

type Resolver struct {
	directory *os.File
	ownerUID  uint32
	inspector ReferenceInspector
	observer  LoadedObserver
}

func LoadedName(binding credentialref.StepBinding) string {
	if !credentialref.ValidBinding(binding) {
		return ""
	}
	return LoadedNameForVersion(binding.ConsumerID, binding.ReferenceID, binding.MaterialVersion)
}

// LoadedNameForVersion is stable across inert import and later exact-plan
// staging; it carries no plaintext, profile or controller-host identity.
func LoadedNameForVersion(consumerID, referenceID, materialVersion string) string {
	for _, id := range []string{consumerID, referenceID, materialVersion} {
		if _, err := credentialref.ParseID(id); err != nil {
			return ""
		}
	}
	sum := sha256.Sum256([]byte("native-loaded-credential-v1\x00" + consumerID + "\x00" + referenceID + "\x00" + materialVersion))
	return "credential-" + hex.EncodeToString(sum[:16])
}

func NewResolver(directoryPath string, ownerUID uint32, inspector ReferenceInspector, observer LoadedObserver) (*Resolver, error) {
	if inspector == nil || observer == nil || !filepath.IsAbs(directoryPath) || filepath.Clean(directoryPath) != directoryPath {
		return nil, nativeError(generated.ErrorCodePrerequisiteBlocked, "native-loaded-observer")
	}
	fd, err := unix.Open(directoryPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nativeError(generated.ErrorCodePrerequisiteBlocked, "native-credential-directory")
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != ownerUID || stat.Mode&0o077 != 0 {
		_ = unix.Close(fd)
		return nil, nativeError(generated.ErrorCodeAuthorizationDenied, "native-credential-directory")
	}
	return &Resolver{directory: os.NewFile(uintptr(fd), "loaded-credentials"), ownerUID: ownerUID, inspector: inspector, observer: observer}, nil
}

func NewResolverFromEnvironment(ownerUID uint32, inspector ReferenceInspector, observer LoadedObserver) (*Resolver, error) {
	return NewResolver(os.Getenv("CREDENTIALS_DIRECTORY"), ownerUID, inspector, observer)
}

func (resolver *Resolver) Close() error {
	if resolver == nil || resolver.directory == nil {
		return nil
	}
	err := resolver.directory.Close()
	resolver.directory = nil
	return err
}

func (resolver *Resolver) Resolve(ctx context.Context, binding credentialref.StepBinding) (*credentialref.Value, error) {
	if resolver == nil || resolver.directory == nil || resolver.inspector == nil || resolver.observer == nil || ctx == nil || !credentialref.ValidBinding(binding) {
		return nil, nativeError(generated.ErrorCodePrerequisiteBlocked, "native-reference")
	}
	if err := ctx.Err(); err != nil {
		return nil, nativeError(generated.ErrorCodeInterrupted, "native-resolution")
	}
	reference, err := resolver.inspector.GetReference(ctx, binding.ReferenceID)
	if err != nil {
		return nil, nativeError(generated.ErrorCodePrerequisiteBlocked, "applied-reference")
	}
	if reference.ReferenceID != binding.ReferenceID || reference.ConsumerID != binding.ConsumerID || reference.PurposeID != binding.PurposeID || reference.TargetID != binding.TargetID || reference.ResolverID != binding.ResolverID || reference.MaterialVersion != binding.MaterialVersion || reference.Status != "active" || reference.ActivatedAt == nil || reference.RecoveryEpoch != binding.RecoveryEpoch || reference.StateRevision > binding.StateRevision || !slices.Contains(reference.VerifiedConsumerIDs, binding.ConsumerID) {
		return nil, nativeError(generated.ErrorCodePrerequisiteBlocked, "active-consumer-reference")
	}
	loaded, err := resolver.observer.ObserveLoaded(ctx, binding)
	if err != nil || !loaded.RestartObserved || loaded.Name != LoadedName(binding) || loaded.MaterialVersion != binding.MaterialVersion || loaded.CiphertextFingerprint != reference.Fingerprint {
		return nil, nativeError(generated.ErrorCodePrerequisiteBlocked, "loaded-version-unverified")
	}
	raw, err := ReadLoadedBytes(ctx, resolver.directory, loaded.Name, resolver.ownerUID)
	if err != nil {
		return nil, err
	}
	defer wipe(raw)
	value, err := credentialref.NewValue(raw)
	if err != nil {
		return nil, nativeError(generated.ErrorCodeIntegrityFailure, "native-loaded-value")
	}
	return value, nil
}

// ReadLoadedBytes is the shared narrow systemd credential reader used by the
// existing Slack acknowledgement consumer. The caller owns and must wipe the
// returned buffer. This primitive does not establish active-reference status.
func ReadLoadedBytes(ctx context.Context, directory *os.File, name string, ownerUID uint32) ([]byte, error) {
	if ctx == nil || directory == nil || directory.Fd() == 0 || name == "" || filepath.Base(name) != name {
		return nil, nativeError(generated.ErrorCodeInputInvalid, "loaded-credential-name")
	}
	if ctx.Err() != nil {
		return nil, nativeError(generated.ErrorCodeInterrupted, "loaded-credential")
	}
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nativeError(generated.ErrorCodeDependencyUnavailable, "loaded-credential")
	}
	file := os.NewFile(uintptr(fd), "loaded-credential")
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != ownerUID || stat.Mode&0o077 != 0 || stat.Size < 8 || stat.Size > 4096 {
		return nil, nativeError(generated.ErrorCodeAuthorizationDenied, "loaded-credential-file")
	}
	value, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(value) < 8 || len(value) > 4096 || ctx.Err() != nil {
		wipe(value)
		return nil, nativeError(generated.ErrorCodeDependencyUnavailable, "loaded-credential")
	}
	return value, nil
}
