package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Issue223 additive reviewed source sets. Historical seals stay unchanged.
// These permit only the fixed private helper, protected action signer and
// exact native loaded-observation/restart continuation implementation.
type hostActionSourceSeal struct {
	imports []string
	digest  string
}

var hostActionSourceSeals = map[string]hostActionSourceSeal{
	"cmd/vsk-labs|host_action_linux.go,main.go,native_probe_linux.go":                 {imports: []string{"context", "crypto/rand", "encoding/hex", "github.com/vegastack/vegastack-labs/internal/adapter/nativecredential", "github.com/vegastack/vegastack-labs/internal/backup", "github.com/vegastack/vegastack-labs/internal/cli", "github.com/vegastack/vegastack-labs/internal/clientfile", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/release", "github.com/vegastack/vegastack-labs/internal/result", "github.com/vegastack/vegastack-labs/internal/server", "os", "os/signal", "strconv", "syscall", "time"}, digest: "5dc39d44764a6b05c6357a1df8b2a52c08046822332b3a235609f046557c7192"},
	"internal/hostaction|bundle.go,once.go,policy_unix.go,receipt_unix.go,request.go": {imports: []string{"bufio", "bytes", "context", "crypto/ed25519", "crypto/sha256", "encoding/base64", "encoding/hex", "encoding/json", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/strictjson", "golang.org/x/sys/unix", "io", "os", "path/filepath", "regexp", "strings", "sync", "time"}, digest: "7dfad2964ea871079ef0f8d21f257291981513d4a9011e9f640eb21e5a099646"},
	"internal/serverconfig|profile.go,profile_linux.go,restic.go":                     {imports: []string{"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "github.com/vegastack/vegastack-labs/internal/backupidentity", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/principal", "golang.org/x/sys/unix", "io", "io/fs", "net/netip", "net/url", "os", "path/filepath", "regexp", "runtime", "strings", "time"}, digest: "da49bc1e5f096c4d390d32a6fca36d799d0ad6b1797ac0ee7ec98ddc3ec7f471"},
	"internal/adapter/nativecredential|authority_linux.go,effective_policy_linux.go,encrypt_linux.go,inspect_linux.go,lifecycle_verifier_linux.go,loaded_observer.go,loaded_observer_linux.go,native_restart_linux.go,policy_check_linux.go,probe_linux.go,process_observer_linux.go,resolver_linux.go,systemd_linux.go,verify_recovery_linux.go": {imports: []string{"bytes", "context", "crypto/sha256", "crypto/subtle", "encoding/hex", "encoding/json", "errors", "fmt", "github.com/godbus/dbus/v5", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "golang.org/x/sys/unix", "io", "os", "os/exec", "os/user", "path/filepath", "reflect", "regexp", "slices", "strconv", "strings", "syscall", "time"}, digest: "634bae361f5ef0514ac094d69fc95e4e1348b7a4ee5eb526362b3242dd16ce84"},
	"cmd/vsk-labs|host_action_unsupported.go,main.go,native_probe_unsupported.go": {imports: []string{"context", "crypto/rand", "encoding/hex", "github.com/vegastack/vegastack-labs/internal/backup", "github.com/vegastack/vegastack-labs/internal/cli", "github.com/vegastack/vegastack-labs/internal/clientfile", "github.com/vegastack/vegastack-labs/internal/release", "github.com/vegastack/vegastack-labs/internal/result", "github.com/vegastack/vegastack-labs/internal/server", "os", "os/signal", "syscall"}, digest: "02f8f5d872051720681a3cb0d144498008b445df5b636a6caa0cc534ebd4e9b4"},
	"internal/serverconfig|profile.go,profile_unsupported.go,restic.go":           {imports: []string{"bytes", "context", "encoding/hex", "encoding/json", "github.com/vegastack/vegastack-labs/internal/backupidentity", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/principal", "io", "io/fs", "net/netip", "net/url", "path/filepath", "regexp", "strings", "time"}, digest: "003c05a23c53e5c7faa38c6d35a8f5cf07711f5728d9a52db0e3a6d314695936"},
	"internal/hostaction|bundle.go,once.go,platform_unsupported.go,request.go":    {imports: []string{"bufio", "context", "crypto/ed25519", "crypto/sha256", "encoding/base64", "encoding/hex", "encoding/json", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/strictjson", "io", "time"}, digest: "1d810eca1989e9b03400f6e4324c4c79ba359d6a7f38a64aaf47aee4b2373530"},
}

func reviewedHostActionPackage(c checkedSourcePackage, module, relative string) bool {
	if c.listed.ImportPath != module+"/"+relative || len(c.listed.CgoFiles) != 0 {
		return false
	}
	names := append([]string(nil), c.listed.GoFiles...)
	slices.Sort(names)
	seal, ok := hostActionSourceSeals[relative+"|"+strings.Join(names, ",")]
	if !ok {
		return false
	}
	imports := append([]string(nil), c.listed.Imports...)
	slices.Sort(imports)
	expectedImports := append([]string(nil), seal.imports...)
	for i, v := range expectedImports {
		expectedImports[i] = strings.Replace(v, "github.com/vegastack/vegastack-labs/", module+"/", 1)
	}
	slices.Sort(expectedImports)
	return slices.Equal(imports, expectedImports) && digestSourceFiles(c.listed.Dir, names) == seal.digest
}
func reviewedHostActionServerSigner(c checkedSourcePackage, serverImport string) bool {
	if c.listed.ImportPath != serverImport {
		return false
	}
	for _, name := range c.listed.GoFiles {
		if name == "host_action_signer_linux.go" {
			if digestSourceFiles(c.listed.Dir, []string{name}) != hostActionSignerSeal {
				return false
			}
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(c.listed.Dir, name), nil, 0)
		if err != nil {
			return false
		}
		aliases := map[string]bool{}
		for _, i := range f.Imports {
			p, _ := strconv.Unquote(i.Path.Value)
			if p == "crypto/ed25519" {
				alias := "ed25519"
				if i.Name != nil {
					alias = i.Name.Name
				}
				if alias == "." || alias == "_" {
					return false
				}
				aliases[alias] = true
			}
		}
		forbidden := false
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if ok && aliases[id.Name] {
				switch sel.Sel.Name {
				case "Sign", "GenerateKey", "NewKeyFromSeed", "PrivateKey":
					forbidden = true
				}
			}
			return !forbidden
		})
		if forbidden {
			return false
		}
	}
	return true
}

const hostActionSignerSeal = "46f8d5149d52b0ea959356af3880c6b946459a9425390c286eaac1612ccae81f"
