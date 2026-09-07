// Package platformpath resolves portable client directories without touching
// the filesystem. Callers can inject operating-system and path behavior so the
// same contract is testable on every build host.
package platformpath

import (
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

const (
	Config  Kind = "config"
	Data    Kind = "data"
	Cache   Kind = "cache"
	Runtime Kind = "runtime"
)

const (
	linuxDirectoryName   = "vsk-labs"
	desktopDirectoryName = "VegaStack Labs"
)

// Kind identifies one portable client directory class.
type Kind string

// PathOps supplies path operations with the semantics of Sources.GOOS.
type PathOps struct {
	Join  func(...string) string
	Clean func(string) string
	IsAbs func(string) bool
}

// Sources supplies all operating-system observations used by a Resolver.
type Sources struct {
	GOOS          string
	LookupEnv     func(string) (string, bool)
	UserHomeDir   func() (string, error)
	UserConfigDir func() (string, error)
	UserCacheDir  func() (string, error)
	Ops           PathOps
}

// Resolver resolves paths from a fixed, injected set of system sources.
type Resolver struct {
	sources Sources
}

// Error is a sanitized path-resolution error. It deliberately retains no
// underlying error or rejected path value.
type Error struct {
	Code   string
	Target string
}

func (err *Error) Error() string {
	return err.Code + ": " + err.Target
}

// New validates sources and constructs a resolver without reading the host.
func New(sources Sources) (*Resolver, error) {
	if sources.GOOS == "" || sources.LookupEnv == nil || sources.UserHomeDir == nil ||
		sources.UserConfigDir == nil || sources.UserCacheDir == nil ||
		sources.Ops.Join == nil || sources.Ops.Clean == nil || sources.Ops.IsAbs == nil {
		return nil, newError(generated.ErrorCodeInputInvalid, "sources")
	}
	return &Resolver{sources: sources}, nil
}

// Resolve returns an absolute, clean client directory. An explicit override is
// used as-is after validation; the resolver never creates or inspects it.
func (resolver *Resolver) Resolve(kind Kind, override string) (string, error) {
	if !knownKind(kind) {
		return "", newError(generated.ErrorCodeInputInvalid, "kind")
	}
	if resolver == nil {
		return "", newError(generated.ErrorCodeInputInvalid, "resolver")
	}
	if resolver.sources.GOOS != "linux" && resolver.sources.GOOS != "darwin" && resolver.sources.GOOS != "windows" {
		return "", newError(generated.ErrorCodeUnsupportedPlatform, "platform")
	}
	if kind == Runtime && resolver.sources.GOOS != "linux" {
		return "", newError(generated.ErrorCodeUnsupportedPlatform, "runtime")
	}
	if override != "" {
		if !resolver.validAbsolutePath(override) {
			return "", newError(generated.ErrorCodeInputInvalid, "override")
		}
		return override, nil
	}

	switch resolver.sources.GOOS {
	case "linux":
		return resolver.resolveLinux(kind)
	case "darwin":
		return resolver.resolveDesktop(kind)
	case "windows":
		return resolver.resolveDesktop(kind)
	default:
		return "", newError(generated.ErrorCodeUnsupportedPlatform, "platform")
	}
}

func (resolver *Resolver) resolveLinux(kind Kind) (string, error) {
	var environment string
	var fallback []string
	switch kind {
	case Config:
		environment = "XDG_CONFIG_HOME"
		fallback = []string{".config"}
	case Data:
		environment = "XDG_DATA_HOME"
		fallback = []string{".local", "share"}
	case Cache:
		environment = "XDG_CACHE_HOME"
		fallback = []string{".cache"}
	case Runtime:
		environment = "XDG_RUNTIME_DIR"
	}

	base, set := resolver.sources.LookupEnv(environment)
	if !set || base == "" {
		if kind == Runtime {
			return "", newError(generated.ErrorCodeDependencyUnavailable, "runtime")
		}
		home, err := resolver.sources.UserHomeDir()
		if err != nil || !resolver.validAbsolutePath(home) {
			return "", newError(generated.ErrorCodeDependencyUnavailable, string(kind))
		}
		base = resolver.sources.Ops.Join(append([]string{home}, fallback...)...)
	}
	return resolver.joinBase(base, linuxDirectoryName, kind)
}

func (resolver *Resolver) resolveDesktop(kind Kind) (string, error) {
	var (
		base string
		err  error
	)
	if kind == Cache {
		base, err = resolver.sources.UserCacheDir()
	} else {
		base, err = resolver.sources.UserConfigDir()
	}
	if err != nil {
		return "", newError(generated.ErrorCodeDependencyUnavailable, string(kind))
	}
	return resolver.joinBase(base, desktopDirectoryName, kind)
}

func (resolver *Resolver) joinBase(base, child string, kind Kind) (string, error) {
	if !resolver.validAbsolutePath(base) {
		return "", newError(generated.ErrorCodeDependencyUnavailable, string(kind))
	}
	resolved := resolver.sources.Ops.Join(base, child)
	if !resolver.validAbsolutePath(resolved) {
		return "", newError(generated.ErrorCodeDependencyUnavailable, string(kind))
	}
	return resolved, nil
}

func (resolver *Resolver) validAbsolutePath(value string) bool {
	return value != "" && !strings.ContainsRune(value, '\x00') &&
		resolver.sources.Ops.IsAbs(value) && resolver.sources.Ops.Clean(value) == value
}

func knownKind(kind Kind) bool {
	switch kind {
	case Config, Data, Cache, Runtime:
		return true
	default:
		return false
	}
}

func newError(code, target string) *Error {
	return &Error{Code: code, Target: target}
}
