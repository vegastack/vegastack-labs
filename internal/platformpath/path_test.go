package platformpath

import (
	"errors"
	"path"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestResolvePortableDefaults(t *testing.T) {
	tests := []struct {
		goos     string
		kind     Kind
		want     string
		wantCode string
	}{
		{"linux", Config, "/home/test/.config/vsk-labs", ""},
		{"linux", Runtime, "", generated.ErrorCodeDependencyUnavailable},
		{"darwin", Data, "/Users/test/Library/Application Support/VegaStack Labs", ""},
		{"windows", Cache, `C:\Users\test\AppData\Local\VegaStack Labs`, ""},
		{"windows", Runtime, "", generated.ErrorCodeUnsupportedPlatform},
	}
	for _, test := range tests {
		t.Run(test.goos+"/"+string(test.kind), func(t *testing.T) {
			got, err := testResolver(t, test.goos, nil).Resolve(test.kind, "")
			assertPathResult(t, got, err, test.want, test.wantCode)
		})
	}
}

func TestResolveLinuxXDGDirectories(t *testing.T) {
	env := map[string]string{
		"XDG_CONFIG_HOME": "/srv/config",
		"XDG_DATA_HOME":   "/srv/data",
		"XDG_CACHE_HOME":  "/srv/cache",
		"XDG_RUNTIME_DIR": "/run/user/1000",
	}
	resolver := testResolver(t, "linux", env)

	tests := []struct {
		kind Kind
		want string
	}{
		{Config, "/srv/config/vsk-labs"},
		{Data, "/srv/data/vsk-labs"},
		{Cache, "/srv/cache/vsk-labs"},
		{Runtime, "/run/user/1000/vsk-labs"},
	}
	for _, test := range tests {
		got, err := resolver.Resolve(test.kind, "")
		assertPathResult(t, got, err, test.want, "")
	}
}

func TestResolveLinuxHomeFallbacks(t *testing.T) {
	resolver := testResolver(t, "linux", map[string]string{
		"XDG_CONFIG_HOME": "",
		"XDG_DATA_HOME":   "",
		"XDG_CACHE_HOME":  "",
	})

	for _, test := range []struct {
		kind Kind
		want string
	}{
		{Config, "/home/test/.config/vsk-labs"},
		{Data, "/home/test/.local/share/vsk-labs"},
		{Cache, "/home/test/.cache/vsk-labs"},
	} {
		got, err := resolver.Resolve(test.kind, "")
		assertPathResult(t, got, err, test.want, "")
	}
}

func TestResolveMacOSAndWindowsBases(t *testing.T) {
	mac := testResolver(t, "darwin", nil)
	for _, test := range []struct {
		kind Kind
		want string
	}{
		{Config, "/Users/test/Library/Application Support/VegaStack Labs"},
		{Data, "/Users/test/Library/Application Support/VegaStack Labs"},
		{Cache, "/Users/test/Library/Caches/VegaStack Labs"},
	} {
		got, err := mac.Resolve(test.kind, "")
		assertPathResult(t, got, err, test.want, "")
	}

	windows := testResolver(t, "windows", nil)
	for _, test := range []struct {
		kind Kind
		want string
	}{
		{Config, `C:\Users\test\AppData\Roaming\VegaStack Labs`},
		{Data, `C:\Users\test\AppData\Roaming\VegaStack Labs`},
		{Cache, `C:\Users\test\AppData\Local\VegaStack Labs`},
	} {
		got, err := windows.Resolve(test.kind, "")
		assertPathResult(t, got, err, test.want, "")
	}
}

func TestResolveAcceptsSafeAbsoluteOverrides(t *testing.T) {
	tests := []struct {
		goos     string
		override string
	}{
		{"linux", "/tmp/VegaStack Labs/数据"},
		{"darwin", "/Users/test/VegaStack Labs/数据"},
		{"windows", `c:\Users\TEST\VegaStack Labs\数据`},
	}
	for _, test := range tests {
		got, err := testResolver(t, test.goos, nil).Resolve(Data, test.override)
		assertPathResult(t, got, err, test.override, "")
	}
}

func TestRuntimeOverrideDoesNotEnableUnsupportedPlatforms(t *testing.T) {
	for _, test := range []struct {
		goos     string
		override string
	}{
		{"darwin", "/Users/test/run"},
		{"windows", `C:\Users\test\run`},
	} {
		got, err := testResolver(t, test.goos, nil).Resolve(Runtime, test.override)
		assertPathResult(t, got, err, "", generated.ErrorCodeUnsupportedPlatform)
	}
}

func TestResolveRejectsUnsafeOverrides(t *testing.T) {
	tests := []struct {
		goos     string
		override string
	}{
		{"linux", "relative/path"},
		{"linux", "/tmp/../private"},
		{"linux", "/tmp/private\x00canary"},
		{"windows", `relative\path`},
		{"windows", `C:\Users\test\..\private`},
	}
	for _, test := range tests {
		got, err := testResolver(t, test.goos, nil).Resolve(Data, test.override)
		assertPathResult(t, got, err, "", generated.ErrorCodeInputInvalid)
		if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "canary") {
			t.Fatalf("error exposed override content: %v", err)
		}
	}
}

func TestResolveRejectsUnknownKindAndPlatform(t *testing.T) {
	got, err := testResolver(t, "linux", nil).Resolve(Kind("private-kind-canary"), "")
	assertPathResult(t, got, err, "", generated.ErrorCodeInputInvalid)
	if strings.Contains(err.Error(), "private-kind-canary") {
		t.Fatalf("error exposed unknown kind: %v", err)
	}

	got, err = testResolver(t, "plan9", nil).Resolve(Config, "")
	assertPathResult(t, got, err, "", generated.ErrorCodeUnsupportedPlatform)
}

func TestResolveSanitizesMissingAndFailedBases(t *testing.T) {
	sources := posixSources("linux", nil)
	sources.UserHomeDir = func() (string, error) {
		return "", errors.New("private-home-canary")
	}
	resolver, err := New(sources)
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolver.Resolve(Data, "")
	assertPathResult(t, got, err, "", generated.ErrorCodeDependencyUnavailable)
	if strings.Contains(err.Error(), "private-home-canary") {
		t.Fatalf("error exposed underlying failure: %v", err)
	}

	sources = posixSources("darwin", nil)
	sources.UserCacheDir = func() (string, error) { return "", nil }
	resolver, err = New(sources)
	if err != nil {
		t.Fatal(err)
	}
	got, err = resolver.Resolve(Cache, "")
	assertPathResult(t, got, err, "", generated.ErrorCodeDependencyUnavailable)

	sources = windowsSources(nil)
	sources.UserConfigDir = func() (string, error) {
		return "", errors.New("private-windows-canary")
	}
	resolver, err = New(sources)
	if err != nil {
		t.Fatal(err)
	}
	got, err = resolver.Resolve(Config, "")
	assertPathResult(t, got, err, "", generated.ErrorCodeDependencyUnavailable)
	if strings.Contains(err.Error(), "private-windows-canary") {
		t.Fatalf("error exposed underlying failure: %v", err)
	}
}

func TestNewRejectsIncompleteSources(t *testing.T) {
	_, err := New(Sources{GOOS: "linux"})
	assertPathCode(t, err, generated.ErrorCodeInputInvalid)
}

func TestSystemConstructsResolver(t *testing.T) {
	resolver, err := System()
	if err != nil {
		t.Fatal(err)
	}
	if resolver == nil {
		t.Fatal("System returned a nil resolver")
	}
}

func assertPathResult(t *testing.T, got string, err error, want, wantCode string) {
	t.Helper()
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	if wantCode == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	assertPathCode(t, err, wantCode)
}

func assertPathCode(t *testing.T, err error, want string) {
	t.Helper()
	var pathErr *Error
	if !errors.As(err, &pathErr) {
		t.Fatalf("error = %v, want *Error", err)
	}
	if pathErr.Code != want {
		t.Fatalf("code = %q, want %q", pathErr.Code, want)
	}
}

func testResolver(t *testing.T, goos string, env map[string]string) *Resolver {
	t.Helper()
	var sources Sources
	if goos == "windows" {
		sources = windowsSources(env)
	} else {
		sources = posixSources(goos, env)
	}
	resolver, err := New(sources)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func posixSources(goos string, env map[string]string) Sources {
	return Sources{
		GOOS:      goos,
		LookupEnv: lookupMap(env),
		UserHomeDir: func() (string, error) {
			if goos == "darwin" {
				return "/Users/test", nil
			}
			return "/home/test", nil
		},
		UserConfigDir: func() (string, error) {
			return "/Users/test/Library/Application Support", nil
		},
		UserCacheDir: func() (string, error) {
			return "/Users/test/Library/Caches", nil
		},
		Ops: PathOps{Join: path.Join, Clean: path.Clean, IsAbs: path.IsAbs},
	}
}

func windowsSources(env map[string]string) Sources {
	return Sources{
		GOOS:      "windows",
		LookupEnv: lookupMap(env),
		UserHomeDir: func() (string, error) {
			return `C:\Users\test`, nil
		},
		UserConfigDir: func() (string, error) {
			return `C:\Users\test\AppData\Roaming`, nil
		},
		UserCacheDir: func() (string, error) {
			return `C:\Users\test\AppData\Local`, nil
		},
		Ops: PathOps{Join: windowsJoin, Clean: windowsClean, IsAbs: windowsIsAbs},
	}
}

func lookupMap(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func windowsJoin(parts ...string) string {
	return windowsClean(strings.Join(parts, `\`))
}

func windowsClean(value string) string {
	drive := ""
	if len(value) >= 3 && value[1] == ':' && (value[2] == '\\' || value[2] == '/') {
		drive = value[:3]
		value = value[3:]
	}
	value = strings.ReplaceAll(value, "/", `\`)
	cleaned := path.Clean(strings.ReplaceAll(value, `\`, "/"))
	cleaned = strings.ReplaceAll(cleaned, "/", `\`)
	if cleaned == "." {
		cleaned = ""
	}
	return drive + cleaned
}

func windowsIsAbs(value string) bool {
	return len(value) >= 3 && value[1] == ':' && (value[2] == '\\' || value[2] == '/')
}
