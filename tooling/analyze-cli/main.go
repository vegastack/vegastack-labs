// Command analyze-cli performs the AST and type-based source checks used by
// tooling/verify-cli.mjs. It is development tooling and is not shipped.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type module struct {
	Path string
	Main bool
}

type listedPackage struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	CgoFiles   []string
	Imports    []string
	Export     string
	Module     *module
	Standard   bool
}

type analysis struct {
	GeneratedCommandsReference  bool     `json:"generatedCommandsReference"`
	GeneratedEndpointsReference bool     `json:"generatedEndpointsReference"`
	HandwrittenRegistry         bool     `json:"handwrittenRegistry"`
	ReleaseArtifactExecution    bool     `json:"releaseArtifactExecution"`
	ReleaseNetworkAccess        bool     `json:"releaseNetworkAccess"`
	SQLiteAccess                bool     `json:"sqliteAccess"`
	ShellDispatch               bool     `json:"shellDispatch"`
	StateExportTrust            bool     `json:"stateExportTrust"`
	StateExportReleaseCoupling  bool     `json:"stateExportReleaseCoupling"`
	ControlSQLiteAccess         bool     `json:"controlSQLiteAccess"`
	ControlShellDispatch        bool     `json:"controlShellDispatch"`
	ControlGoogleAccess         bool     `json:"controlGoogleAccess"`
	ControlProviderAccess       bool     `json:"controlProviderAccess"`
	ControlArbitraryHTTP        bool     `json:"controlArbitraryHTTP"`
	ControlServerPath           bool     `json:"controlServerPath"`
	InventoryDirectDomain       bool     `json:"inventoryDirectDomain"`
	LocalClientBoundary         bool     `json:"localClientBoundary"`
	TargetsAnalyzed             []string `json:"targetsAnalyzed"`
}

type sourcePackage struct {
	listed listedPackage
	files  []*ast.File
	info   *types.Info
}

type analysisContext struct {
	generatedImport string
	derivedCommands map[*types.Named]bool
}

type packageImporter struct {
	checked  map[string]*types.Package
	fallback types.Importer
}

func (loader packageImporter) Import(path string) (*types.Package, error) {
	if found := loader.checked[path]; found != nil {
		return found, nil
	}
	return loader.fallback.Import(path)
}

func main() {
	root := flag.String("root", "", "repository root to inspect")
	goos := flag.String("goos", "", "target GOOS")
	goarch := flag.String("goarch", "", "target GOARCH")
	flag.Parse()
	if *root == "" || *goos == "" || *goarch == "" {
		fmt.Fprintln(os.Stderr, "analyze-cli: --root, --goos and --goarch are required")
		os.Exit(2)
	}

	result, err := analyze(*root, *goos, *goarch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyze-cli: %v\n", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "analyze-cli: encode result: %v\n", err)
		os.Exit(1)
	}
}

func analyze(root, goos, goarch string) (analysis, error) {
	packages, err := listPackages(root, goos, goarch)
	if err != nil {
		return analysis{}, fmt.Errorf("list %s/%s dependency closure: %w", goos, goarch, err)
	}
	result, err := analyzeTarget(packages)
	if err != nil {
		return analysis{}, fmt.Errorf("analyze %s/%s dependency closure: %w", goos, goarch, err)
	}
	modulePackages, err := listModulePackages(root, goos, goarch)
	if err != nil {
		return analysis{}, fmt.Errorf("list %s/%s module packages: %w", goos, goarch, err)
	}
	result.SQLiteAccess = hasSQLiteAccessOutsideStore(modulePackages)
	moduleTrust, moduleReleaseCoupling := stateExportFacts(modulePackages)
	result.StateExportTrust = result.StateExportTrust || moduleTrust
	result.StateExportReleaseCoupling = result.StateExportReleaseCoupling || moduleReleaseCoupling
	result.TargetsAnalyzed = []string{goos + "/" + goarch}
	return result, nil
}

func stateExportFacts(packages []listedPackage) (bool, bool) {
	modulePath := ""
	for _, candidate := range packages {
		if candidate.Module != nil && candidate.Module.Main && candidate.Module.Path != "" {
			modulePath = candidate.Module.Path
			break
		}
	}
	if modulePath == "" {
		return true, true
	}
	exportImport := modulePath + "/internal/stateexport"
	releaseImport := modulePath + "/internal/release"
	storeImport := modulePath + "/internal/store"
	trust := false
	coupling := false
	for _, candidate := range packages {
		for _, name := range append(append([]string(nil), candidate.GoFiles...), candidate.CgoFiles...) {
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(candidate.Dir, name), nil, parser.SkipObjectResolution)
			if err != nil {
				return true, true
			}
			aliases := make(map[string]string)
			sensitive := candidate.ImportPath == exportImport || (candidate.ImportPath == storeImport && strings.HasPrefix(name, "inventory_export"))
			for _, imported := range file.Imports {
				path, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					return true, true
				}
				alias := filepath.Base(path)
				if imported.Name != nil && imported.Name.Name != "_" && imported.Name.Name != "." {
					alias = imported.Name.Name
				}
				aliases[alias] = path
				if sensitive && path == "crypto/ed25519" {
					trust = true
				}
				if sensitive && path == releaseImport {
					coupling = true
				}
			}
			ast.Inspect(file, func(node ast.Node) bool {
				if sensitive {
					switch value := node.(type) {
					case *ast.Ident:
						normalized := strings.ToLower(strings.ReplaceAll(value.Name, "_", ""))
						if value.Name == "ReleaseTrustPolicy" {
							coupling = true
						}
						if normalized == "privatekey" || normalized == "signingseed" || normalized == "privatekeybytes" {
							trust = true
						}
					case *ast.BasicLit:
						if value.Kind == token.STRING {
							decoded, _ := strconv.Unquote(value.Value)
							if strings.Contains(decoded, "verified-against-supplied-policy") || strings.Contains(decoded, "release-trust-policy") {
								coupling = true
							}
						}
					}
				}
				literal, ok := node.(*ast.CompositeLit)
				if !ok {
					return true
				}
				selector, ok := unparenthesized(literal.Type).(*ast.SelectorExpr)
				if !ok {
					return true
				}
				prefix, prefixOK := selector.X.(*ast.Ident)
				if !prefixOK || selector.Sel.Name != "Config" || aliases[prefix.Name] != exportImport {
					return true
				}
				for _, element := range literal.Elts {
					pair, ok := element.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, keyOK := pair.Key.(*ast.Ident)
					if !keyOK || (key.Name != "Signer" && key.Name != "Verifier") {
						continue
					}
					identifier, isIdentifier := unparenthesized(pair.Value).(*ast.Ident)
					if !isIdentifier || identifier.Name != "nil" {
						trust = true
					}
				}
				return true
			})
		}
	}
	return trust, coupling
}

func listPackages(root, goos, goarch string) ([]listedPackage, error) {
	command := exec.Command("go", "list", "-deps", "-export", "-json", "./cmd/vsk-labs")
	command.Dir = root
	command.Env = targetEnvironment(goos, goarch)
	output, err := command.Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return nil, fmt.Errorf("go list: %s", strings.TrimSpace(string(exitError.Stderr)))
		}
		return nil, fmt.Errorf("go list: %w", err)
	}

	decoder := json.NewDecoder(strings.NewReader(string(output)))
	var packages []listedPackage
	for {
		var candidate listedPackage
		if err := decoder.Decode(&candidate); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		packages = append(packages, candidate)
	}
	return packages, nil
}

func listModulePackages(root, goos, goarch string) ([]listedPackage, error) {
	command := exec.Command("go", "list", "-json", "./...")
	command.Dir = root
	command.Env = targetEnvironment(goos, goarch)
	output, err := command.Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return nil, fmt.Errorf("go list: %s", strings.TrimSpace(string(exitError.Stderr)))
		}
		return nil, fmt.Errorf("go list: %w", err)
	}

	decoder := json.NewDecoder(strings.NewReader(string(output)))
	var packages []listedPackage
	for {
		var candidate listedPackage
		if err := decoder.Decode(&candidate); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		if candidate.Module != nil && candidate.Module.Main {
			packages = append(packages, candidate)
		}
	}
	return packages, nil
}

func hasSQLiteAccessOutsideStore(packages []listedPackage) bool {
	if len(packages) == 0 {
		return true
	}
	modulePath := ""
	for _, candidate := range packages {
		if candidate.Module != nil && candidate.Module.Main && candidate.Module.Path != "" {
			modulePath = candidate.Module.Path
			break
		}
	}
	if modulePath == "" {
		return true
	}
	storeImport := modulePath + "/internal/store"
	for _, candidate := range packages {
		if candidate.ImportPath == storeImport || strings.HasPrefix(candidate.ImportPath, storeImport+"/") {
			continue
		}
		for _, imported := range candidate.Imports {
			switch imported {
			case "database/sql", "github.com/ncruces/go-sqlite3", "github.com/ncruces/go-sqlite3/driver":
				return true
			}
		}
	}
	return false
}

func targetEnvironment(goos, goarch string) []string {
	environment := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "CGO_ENABLED=") || strings.HasPrefix(entry, "GOOS=") || strings.HasPrefix(entry, "GOARCH=") {
			continue
		}
		environment = append(environment, entry)
	}
	return append(environment, "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
}

func analyzeTarget(listed []listedPackage) (analysis, error) {
	if len(listed) == 0 {
		return analysis{}, errors.New("dependency closure contains no in-module packages")
	}
	modulePath := ""
	var inModule []listedPackage
	for _, candidate := range listed {
		if candidate.Module != nil && candidate.Module.Main {
			inModule = append(inModule, candidate)
			if candidate.Module.Path != "" {
				modulePath = candidate.Module.Path
			}
		}
	}
	if modulePath == "" || len(inModule) == 0 {
		return analysis{}, errors.New("main module path is unavailable")
	}
	mainImport := modulePath + "/cmd/vsk-labs"
	generatedImport := modulePath + "/internal/generated"
	releaseImport := modulePath + "/internal/release"
	stateExportImport := modulePath + "/internal/stateexport"
	identityImport := modulePath + "/internal/identity"
	apiImport := modulePath + "/internal/api"
	serverImport := modulePath + "/internal/server"
	localAPIImport := modulePath + "/internal/localapi"
	localTransportImport := modulePath + "/internal/localtransport"
	cliImport := modulePath + "/internal/cli"
	clientFileImport := modulePath + "/internal/clientfile"
	serverConfigImport := modulePath + "/internal/serverconfig"
	if !containsPackage(inModule, mainImport) || !containsPackage(inModule, generatedImport) {
		return analysis{}, errors.New("runtime dependency closure omits the executable or generated package")
	}

	checked := make(map[string]*types.Package)
	targetLoader, err := exportDataImporter(listed)
	if err != nil {
		return analysis{}, err
	}
	loader := packageImporter{checked: checked, fallback: targetLoader}
	var result analysis
	standardPackages := make(map[string]bool)
	for _, candidate := range listed {
		if candidate.Standard {
			standardPackages[candidate.ImportPath] = true
		}
	}
	standardNetworkPackages := standardNetworkClosure(listed)
	result.LocalClientBoundary = true
	localClosure := moduleDependencyClosure(inModule, localAPIImport)
	controlClosure := moduleDependencyClosure(inModule, cliImport)
	for importPath := range moduleDependencyClosure(inModule, clientFileImport) {
		controlClosure[importPath] = true
	}
	controlClosure[mainImport] = true
	for _, candidate := range inModule {
		if candidate.ImportPath != mainImport {
			continue
		}
		for _, imported := range candidate.Imports {
			if imported == serverImport || strings.HasPrefix(imported, serverImport+"/") {
				continue
			}
			for importPath := range moduleDependencyClosure(inModule, imported) {
				controlClosure[importPath] = true
			}
		}
	}
	if len(localClosure) > 0 && !reviewedLocalClientDependencies(localClosure, modulePath, localAPIImport, localTransportImport) {
		result.LocalClientBoundary = false
	}
	for _, candidate := range inModule {
		parsed, err := parseAndCheck(candidate, loader)
		if err != nil {
			return analysis{}, err
		}
		checked[candidate.ImportPath] = parsed.infoPackage()
		if candidate.ImportPath == mainImport && !reviewedMainComposition(parsed, modulePath, cliImport, clientFileImport, releaseImport, serverImport) {
			result.ControlProviderAccess = true
		}
		if candidate.ImportPath != localAPIImport && candidate.ImportPath != localTransportImport && containsString(candidate.Imports, localTransportImport) {
			result.LocalClientBoundary = false
		}
		if localClosure[candidate.ImportPath] && !reviewedLocalClientPackage(parsed, modulePath, localAPIImport, localTransportImport) {
			result.LocalClientBoundary = false
		}
		isReleasePackage := candidate.ImportPath == releaseImport || strings.HasPrefix(candidate.ImportPath, releaseImport+"/")
		isControlPackage := controlClosure[candidate.ImportPath]
		isControlCapabilityPackage := isControlPackage && !(localClosure[candidate.ImportPath] && !result.LocalClientBoundary)
		inspectControlPaths := isControlPackage && candidate.ImportPath != generatedImport && candidate.ImportPath != serverConfigImport
		for _, imported := range candidate.Imports {
			if imported == "os/exec" && !isReleasePackage {
				result.ShellDispatch = true
			}
			switch imported {
			case "crypto/ecdsa", "crypto/ed25519":
				result.StateExportTrust = true
			case "crypto/rsa":
				// The remote-identity adapter verifies RSA public keys. Keep the
				// executable-wide signing guard everywhere else; state-export
				// composition is independently checked below.
				if candidate.ImportPath != identityImport {
					result.StateExportTrust = true
				}
			}
			if isReleasePackage {
				if standardNetworkPackages[imported] || imported == "github.com/sigstore/sigstore-go/pkg/tuf" {
					result.ReleaseNetworkAccess = true
				}
				switch imported {
				case "os/exec", "plugin":
					result.ReleaseArtifactExecution = true
				}
			}
			if isControlCapabilityPackage {
				switch imported {
				case "database/sql", "github.com/ncruces/go-sqlite3", "github.com/ncruces/go-sqlite3/driver":
					result.ControlSQLiteAccess = true
				case "os/exec", "plugin":
					result.ControlShellDispatch = true
				case "crypto/tls", "syscall":
					if !reviewedControlNetworkImport(parsed, imported, mainImport, localAPIImport, localTransportImport, serverConfigImport) {
						result.ControlArbitraryHTTP = true
					}
				}
				if standardNetworkPackages[imported] && !reviewedControlNetworkImport(parsed, imported, mainImport, localAPIImport, localTransportImport, serverConfigImport) {
					result.ControlArbitraryHTTP = true
				}
				if !reviewedControlExternalImport(parsed, imported, standardPackages[imported], modulePath, localAPIImport, clientFileImport, serverConfigImport, releaseImport) {
					result.ControlProviderAccess = true
				}
				if strings.Contains(imported, "google.golang.org") || strings.Contains(imported, "/google") || strings.Contains(imported, "sheets") {
					result.ControlGoogleAccess = true
				}
				if strings.HasPrefix(imported, modulePath+"/internal/inventory") || strings.HasPrefix(imported, modulePath+"/internal/profiles/") || imported == modulePath+"/internal/store" || imported == modulePath+"/internal/stateexport" {
					result.InventoryDirectDomain = true
				}
				if strings.Contains(imported, "/cloudflare") || strings.Contains(imported, "/coolify") || strings.Contains(imported, "/harbor") || strings.Contains(imported, "/onepassword") {
					result.ControlProviderAccess = true
				}
			}
		}
		inspectPackage(parsed, generatedImport, stateExportImport, isReleasePackage, candidate.ImportPath == apiImport || candidate.ImportPath == localAPIImport, inspectControlPaths, &result)
	}
	return result, nil
}

const reviewedMainCompositionDigest = "a7f7b29ce0e32577cfd392cf9d33e823a6807c85f6708f5f910ad632a4bd8061"

func reviewedMainComposition(candidate checkedSourcePackage, modulePath, cliImport, clientFileImport, releaseImport, serverImport string) bool {
	approvedInternal := map[string]bool{
		cliImport:                       true,
		clientFileImport:                true,
		releaseImport:                   true,
		modulePath + "/internal/result": true,
		serverImport:                    true,
	}
	extendedComposition := false
	for _, imported := range candidate.listed.Imports {
		if strings.HasPrefix(imported, modulePath+"/") {
			if !approvedInternal[imported] {
				return false
			}
			if imported != cliImport {
				extendedComposition = true
			}
		}
	}
	if !extendedComposition {
		return true
	}
	names := append([]string(nil), candidate.listed.GoFiles...)
	sort.Strings(names)
	return digestSourceFiles(candidate.listed.Dir, names) == reviewedMainCompositionDigest
}

func standardNetworkClosure(packages []listedPackage) map[string]bool {
	standard := make(map[string]listedPackage)
	for _, candidate := range packages {
		if candidate.Standard {
			standard[candidate.ImportPath] = candidate
		}
	}
	capable := map[string]bool{"net": true}
	for changed := true; changed; {
		changed = false
		for importPath, candidate := range standard {
			if capable[importPath] {
				continue
			}
			for _, imported := range candidate.Imports {
				if capable[imported] {
					capable[importPath] = true
					changed = true
					break
				}
			}
		}
	}
	return capable
}

func reviewedControlNetworkImport(candidate checkedSourcePackage, imported, mainImport, localAPIImport, localTransportImport, serverConfigImport string) bool {
	switch candidate.listed.ImportPath {
	case mainImport:
		return imported == "syscall" && reviewedMainSyscallUse(candidate)
	case localAPIImport:
		return imported == "net" && reviewedLocalAPISource(candidate)
	case localTransportImport:
		return (imported == "net" || imported == "net/http") && reviewedLocalTransportPackage(candidate)
	case serverConfigImport:
		return (imported == "net/url" || imported == "net/netip") && reviewedControlPlatformSource(candidate, "serverconfig")
	default:
		return false
	}
}

func reviewedMainSyscallUse(candidate checkedSourcePackage) bool {
	valid := true
	for _, file := range candidate.files {
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			function, ok := candidate.info.ObjectOf(selector.Sel).(*types.Func)
			if ok && function.Pkg() != nil && function.Pkg().Path() == "syscall" {
				valid = false
				return false
			}
			return true
		})
	}
	return valid
}

func reviewedControlExternalImport(candidate checkedSourcePackage, imported string, standard bool, modulePath, localAPIImport, clientFileImport, serverConfigImport, releaseImport string) bool {
	if strings.HasPrefix(imported, modulePath+"/") || standard {
		return true
	}
	candidatePath := candidate.listed.ImportPath
	if candidatePath == localAPIImport && imported == "golang.org/x/sys/unix" && reviewedLocalAPISource(candidate) {
		return true
	}
	if candidatePath == clientFileImport && (imported == "golang.org/x/sys/unix" || imported == "golang.org/x/sys/windows") && reviewedControlPlatformSource(candidate, "clientfile") {
		return true
	}
	if candidatePath == serverConfigImport && imported == "golang.org/x/sys/unix" && reviewedControlPlatformSource(candidate, "serverconfig") {
		return true
	}
	if candidatePath == releaseImport {
		switch imported {
		case "github.com/sigstore/sigstore-go/pkg/bundle", "github.com/sigstore/sigstore-go/pkg/root", "github.com/sigstore/sigstore-go/pkg/verify":
			return true
		}
	}
	return false
}

func reviewedControlPlatformSource(candidate checkedSourcePackage, kind string) bool {
	names := append([]string(nil), candidate.listed.GoFiles...)
	sort.Strings(names)
	var expected string
	switch kind {
	case "clientfile":
		expected = "20cf2e7ef6da35560d59b88a69e75391ae58b22a22d88da619000e019adaf28b"
		if containsString(names, "read_unix.go") {
			expected = "20230c50a5ab877241ef447281ade07e836298d3cde4f85d187b304f35aafae2"
		}
	case "serverconfig":
		expected = "996c3c80ae4cf23f9287144d6e35bb11462ea4dc56ded19252e7d7a4a48f94aa"
		if containsString(names, "profile_linux.go") {
			expected = "931b729297a09edb6fca13a5c69187488d7fac234f30df1444e8be5c024d2c96"
		}
	default:
		return false
	}
	return digestSourceFiles(candidate.listed.Dir, names) == expected
}

func moduleDependencyClosure(packages []listedPackage, root string) map[string]bool {
	byImport := make(map[string]listedPackage, len(packages))
	for _, candidate := range packages {
		byImport[candidate.ImportPath] = candidate
	}
	if _, ok := byImport[root]; !ok {
		return nil
	}
	closure := make(map[string]bool)
	pending := []string{root}
	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if closure[current] {
			continue
		}
		closure[current] = true
		for _, imported := range byImport[current].Imports {
			if _, ok := byImport[imported]; ok {
				pending = append(pending, imported)
			}
		}
	}
	return closure
}

func reviewedLocalClientDependencies(closure map[string]bool, modulePath, localAPIImport, localTransportImport string) bool {
	approved := map[string]bool{
		localAPIImport:                        true,
		localTransportImport:                  true,
		modulePath + "/internal/failure":      true,
		modulePath + "/internal/generated":    true,
		modulePath + "/internal/principal":    true,
		modulePath + "/internal/result":       true,
		modulePath + "/internal/runprotocol":  true,
		modulePath + "/internal/serverconfig": true,
		modulePath + "/internal/strictjson":   true,
	}
	for importPath := range closure {
		if !approved[importPath] {
			return false
		}
	}
	return true
}

func reviewedLocalClientPackage(candidate checkedSourcePackage, modulePath, localAPIImport, localTransportImport string) bool {
	approvedExternal := func(imported string) bool {
		return imported == "golang.org/x/sys/unix" || imported == "github.com/go-jose/go-jose/v4" || imported == "github.com/go-jose/go-jose/v4/jwt"
	}
	if candidate.listed.ImportPath == localTransportImport {
		return reviewedLocalTransportPackage(candidate)
	}
	if candidate.listed.ImportPath != localAPIImport {
		for _, imported := range candidate.listed.Imports {
			if imported == "os/exec" || imported == "plugin" || imported == "database/sql" {
				return false
			}
			if !strings.HasPrefix(imported, modulePath+"/") && strings.Contains(imported, ".") && !approvedExternal(imported) {
				return false
			}
		}
		return true
	}
	if !reviewedLocalAPISource(candidate) {
		return false
	}
	for _, imported := range candidate.listed.Imports {
		if imported == "os/exec" || imported == "plugin" || imported == "database/sql" || imported == "net/http" || imported == "net/url" || imported == "crypto/tls" || imported == "reflect" || imported == "unsafe" || imported == "syscall" {
			return false
		}
		if strings.HasPrefix(imported, modulePath+"/") || !strings.Contains(imported, ".") || approvedExternal(imported) {
			continue
		}
		// The reviewed local client has no third-party dependency. Provider SDKs
		// and any future external transport must pass a separate design review.
		return false
	}
	approvedCallbacks := reviewedLocalCallbacks(candidate)
	valid := true
	for _, file := range candidate.files {
		directCallees := make(map[ast.Expr]bool)
		ast.Inspect(file, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				directCallees[unparenthesized(call.Fun)] = true
			}
			return true
		})
		ast.Inspect(file, func(node ast.Node) bool {
			if !valid {
				return false
			}
			if selector, ok := node.(*ast.SelectorExpr); ok {
				function, functionOK := candidate.info.ObjectOf(selector.Sel).(*types.Func)
				if functionOK && function.Pkg() != nil && reviewedNetworkFunctionPackage(function.Pkg().Path()) && !directCallees[unparenthesized(selector)] {
					valid = false
					return false
				}
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if variable := calledFunctionVariable(call.Fun, candidate.info); variable != nil {
				if !reviewedLocalCallbackCall(call.Fun, variable, candidate.info, localAPIImport, approvedCallbacks) {
					valid = false
					return false
				}
				return true
			}
			function := calledFunction(call.Fun, candidate.info)
			if function == nil {
				callee := unparenthesized(call.Fun)
				if identifier, ok := callee.(*ast.Ident); ok {
					if _, builtin := candidate.info.ObjectOf(identifier).(*types.Builtin); builtin {
						return true
					}
				}
				if _, literal := callee.(*ast.FuncLit); !literal {
					if functionType := candidate.info.TypeOf(callee); functionType != nil {
						if _, indirect := types.Unalias(functionType).Underlying().(*types.Signature); indirect {
							valid = false
							return false
						}
					}
				}
				return true
			}
			if function.Pkg() == nil {
				return true
			}
			switch function.Pkg().Path() {
			case "net":
				valid = reviewedUnixDial(function, call)
			case "net/http", "net/url", "crypto/tls":
				valid = false
			}
			return valid
		})
	}
	return valid
}

const (
	reviewedLocalAPILinuxDigest       = "b88b7e4101be9b264fc48a0347d2bfb82aaea745df480010373f8d1d1eb50f29"
	reviewedLocalAPIUnsupportedDigest = "917d9db1b5deb825ad2e238847d8ddbfec9ea667ef00e06698bafa2bbce7a513"
)

// reviewedLocalAPISource seals every production source file in the package
// that can reach the value-only local transport. This makes caller provenance
// part of the reviewed boundary: adding a raw forwarding helper, a new client
// method, an init hook, a target-specific file, or a syscall path fails closed
// until the complete package is independently reviewed and resealed.
func reviewedLocalAPISource(candidate checkedSourcePackage) bool {
	names := append([]string(nil), candidate.listed.GoFiles...)
	sort.Strings(names)
	expected := reviewedLocalAPIUnsupportedDigest
	if containsString(names, "listener_linux.go") {
		expected = reviewedLocalAPILinuxDigest
	}
	return digestSourceFiles(candidate.listed.Dir, names) == expected
}

func reviewedNetworkFunctionPackage(packagePath string) bool {
	switch packagePath {
	case "net", "net/http", "net/url", "crypto/tls":
		return true
	default:
		return false
	}
}

func reviewedLocalCallbackCall(expression ast.Expr, variable *types.Var, info *types.Info, localAPIImport string, approved map[*types.Var]bool) bool {
	if approved[variable] {
		return true
	}
	selector, ok := unparenthesized(expression).(*ast.SelectorExpr)
	return ok && variable.IsField() && variable.Name() == "onClose" && typeNamed(info.TypeOf(selector.X), localAPIImport, "authenticatedConn")
}

func typeNamed(value types.Type, packagePath, name string) bool {
	for {
		value = types.Unalias(value)
		pointer, ok := value.(*types.Pointer)
		if !ok {
			break
		}
		value = pointer.Elem()
	}
	named, ok := value.(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == packagePath && named.Obj().Name() == name
}

func calledFunctionVariable(expression ast.Expr, info *types.Info) *types.Var {
	var object types.Object
	switch typed := unparenthesized(expression).(type) {
	case *ast.Ident:
		object = info.ObjectOf(typed)
	case *ast.SelectorExpr:
		object = info.ObjectOf(typed.Sel)
	}
	variable, ok := object.(*types.Var)
	if !ok {
		return nil
	}
	if _, ok := types.Unalias(variable.Type()).Underlying().(*types.Signature); !ok {
		return nil
	}
	return variable
}

// reviewedLocalCallbacks names the three function values required by the
// socket implementation and binds them to their exact declarations. A caller
// cannot evade the network guard by reusing one of these names in another
// scope or by assigning a package function to a local variable.
func reviewedLocalCallbacks(candidate checkedSourcePackage) map[*types.Var]bool {
	approved := make(map[*types.Var]bool)
	for _, file := range candidate.files {
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.FuncDecl:
				parameter := ""
				switch typed.Name.Name {
				case "validateTypedResponse":
					parameter = "validate"
				case "newAuthenticatedConn":
					parameter = "onClose"
				}
				if parameter != "" && typed.Type.Params != nil {
					for _, field := range typed.Type.Params.List {
						for _, name := range field.Names {
							if name.Name == parameter {
								if variable, ok := candidate.info.Defs[name].(*types.Var); ok {
									approved[variable] = true
								}
							}
						}
					}
				}
			case *ast.AssignStmt:
				if len(typed.Lhs) != 2 || len(typed.Rhs) != 1 {
					return true
				}
				call, ok := unparenthesized(typed.Rhs[0]).(*ast.CallExpr)
				if !ok {
					return true
				}
				function := calledFunction(call.Fun, candidate.info)
				if function == nil || function.Pkg() == nil || function.Pkg().Path() != "context" || function.Name() != "WithTimeout" {
					return true
				}
				name, ok := unparenthesized(typed.Lhs[1]).(*ast.Ident)
				if !ok {
					return true
				}
				object := candidate.info.ObjectOf(name)
				if variable, ok := object.(*types.Var); ok {
					approved[variable] = true
				}
			}
			return true
		})
	}
	return approved
}

func reviewedUnixDial(function *types.Func, call *ast.CallExpr) bool {
	switch function.Name() {
	case "DialContext":
		if len(call.Args) != 3 {
			return false
		}
		signature, ok := function.Type().(*types.Signature)
		if !ok || signature.Recv() == nil || !strings.Contains(types.TypeString(signature.Recv().Type(), nil), "net.Dialer") {
			return false
		}
		return exactString(call.Args[1], "unix")
	case "ListenUnix":
		return len(call.Args) == 2 && exactString(call.Args[0], "unix")
	case "AcceptUnix", "SetUnlinkOnClose", "SyscallConn", "Close", "Addr":
		return true
	default:
		return false
	}
}

const reviewedLocalTransportDigest = "b7363c8b9c166d1a71b63a9f1912fc3d578389a5d27bebbb4ddd6e12851c639e"

func reviewedLocalTransportPackage(candidate checkedSourcePackage) bool {
	approvedImports := map[string]bool{
		"bytes": true, "context": true, "errors": true, "io": true, "net": true,
		"net/http": true, "path": true, "strings": true, "time": true,
	}
	if len(candidate.listed.GoFiles) != 1 || candidate.listed.GoFiles[0] != "transport.go" || len(candidate.listed.Imports) != len(approvedImports) {
		return false
	}
	for _, imported := range candidate.listed.Imports {
		if !approvedImports[imported] {
			return false
		}
	}
	expectedAPI := []string{
		"ErrInvalid", "ErrRedirect", "ErrUnavailable", "Method", "MethodGet", "MethodPost", "Request", "Response", "RoundTrip",
		"StatusBadGateway", "StatusBadRequest", "StatusConflict", "StatusForbidden", "StatusNotFound", "StatusOK", "StatusPreconditionFailed",
		"StatusRequestTimeout", "StatusServiceUnavailable", "StatusUnauthorized",
	}
	actualAPI := candidate.typed.Scope().Names()
	actualAPI = slicesMatching(actualAPI, ast.IsExported)
	if len(actualAPI) != len(expectedAPI) {
		return false
	}
	for index := range expectedAPI {
		if actualAPI[index] != expectedAPI[index] {
			return false
		}
	}
	return digestSourceFiles(candidate.listed.Dir, candidate.listed.GoFiles) == reviewedLocalTransportDigest
}

func digestSourceFiles(directory string, names []string) string {
	hash := sha256.New()
	for _, name := range names {
		content, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return ""
		}
		_, _ = hash.Write([]byte(name))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(content)
		_, _ = hash.Write([]byte{0})
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func slicesMatching(values []string, keep func(string) bool) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if keep(value) {
			result = append(result, value)
		}
	}
	return result
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func exactString(expression ast.Expr, expected string) bool {
	literal, ok := unparenthesized(expression).(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return false
	}
	value, err := strconv.Unquote(literal.Value)
	return err == nil && value == expected
}

func exportDataImporter(packages []listedPackage) (types.Importer, error) {
	exports := make(map[string]string, len(packages))
	for _, candidate := range packages {
		if candidate.Export != "" {
			exports[candidate.ImportPath] = candidate.Export
		}
	}
	lookup := func(importPath string) (io.ReadCloser, error) {
		filename := exports[importPath]
		if filename == "" {
			return nil, fmt.Errorf("target export data unavailable for %s", importPath)
		}
		return os.Open(filename)
	}
	return importer.ForCompiler(token.NewFileSet(), "gc", lookup), nil
}

func containsPackage(packages []listedPackage, importPath string) bool {
	for _, candidate := range packages {
		if candidate.ImportPath == importPath {
			return true
		}
	}
	return false
}

type checkedSourcePackage struct {
	sourcePackage
	typed *types.Package
}

func (checked checkedSourcePackage) infoPackage() *types.Package { return checked.typed }

func parseAndCheck(candidate listedPackage, loader types.Importer) (checkedSourcePackage, error) {
	fileSet := token.NewFileSet()
	names := append(append([]string(nil), candidate.GoFiles...), candidate.CgoFiles...)
	sort.Strings(names)
	files := make([]*ast.File, 0, len(names))
	for _, name := range names {
		filename := filepath.Join(candidate.Dir, name)
		file, err := parser.ParseFile(fileSet, filename, nil, parser.SkipObjectResolution)
		if err != nil {
			return checkedSourcePackage{}, fmt.Errorf("parse %s: %w", filename, err)
		}
		files = append(files, file)
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
	}
	configuration := types.Config{Importer: loader}
	typed, err := configuration.Check(candidate.ImportPath, fileSet, files, info)
	if err != nil {
		return checkedSourcePackage{}, fmt.Errorf("type-check %s: %w", candidate.ImportPath, err)
	}
	return checkedSourcePackage{
		sourcePackage: sourcePackage{listed: candidate, files: files, info: info},
		typed:         typed,
	}, nil
}

func inspectPackage(candidate checkedSourcePackage, generatedImport, stateExportImport string, isReleasePackage, isAPIPackage, isControlPackage bool, result *analysis) {
	context := analysisContext{
		generatedImport: generatedImport,
		derivedCommands: derivedCommandTypes(candidate, generatedImport),
	}
	for _, file := range candidate.files {
		ast.Inspect(file, func(node ast.Node) bool {
			if isControlPackage && controlNodeUsesServerPath(node) {
				result.ControlServerPath = true
			}
			if selector, ok := node.(*ast.SelectorExpr); ok {
				if object := candidate.info.ObjectOf(selector.Sel); object != nil && object.Pkg() != nil && object.Pkg().Path() == generatedImport && object.Name() == "Endpoints" {
					result.GeneratedEndpointsReference = true
				}
			}
			if isReleasePackage {
				inspectReleaseNode(node, candidate.info, result)
			}
			switch typed := node.(type) {
			case *ast.FuncDecl:
				if functionRecognizesGeneratedCommands(typed, candidate.info, generatedImport) {
					result.GeneratedCommandsReference = true
				}
			case *ast.ValueSpec:
				if candidate.listed.ImportPath != generatedImport && !isAPIPackage && valueSpecIsRegistry(typed, candidate.info, context) {
					result.HandwrittenRegistry = true
				}
			case *ast.AssignStmt:
				if candidate.listed.ImportPath != generatedImport && !isAPIPackage && assignmentIsRegistry(typed, candidate.info, context) {
					result.HandwrittenRegistry = true
				}
				if assignmentProvidesStateExportTrust(typed, candidate.info, stateExportImport) {
					result.StateExportTrust = true
				}
			case *ast.CompositeLit:
				if candidate.listed.ImportPath != generatedImport && !isAPIPackage && isDispatchCollection(candidate.info.TypeOf(typed), context) {
					result.HandwrittenRegistry = true
				}
				if stateExportConfigProvidesTrust(typed, candidate.info, stateExportImport) {
					result.StateExportTrust = true
				}
			case *ast.CallExpr:
				if stateExportNewServiceMayReceiveTrust(typed, candidate.info, stateExportImport) {
					result.StateExportTrust = true
				}
			}
			return true
		})
	}
}

func controlNodeUsesServerPath(node ast.Node) bool {
	switch value := node.(type) {
	case *ast.Ident:
		return value.Name == "InventoryExportRoot" || value.Name == "DatabasePath" || value.Name == "ServerPath"
	case *ast.BasicLit:
		if value.Kind != token.STRING {
			return false
		}
		decoded, err := strconv.Unquote(value.Value)
		return err == nil && (strings.HasPrefix(decoded, "/var/") || strings.Contains(decoded, "control.db") || strings.Contains(decoded, "serverPath"))
	default:
		return false
	}
}

func assignmentProvidesStateExportTrust(statement *ast.AssignStmt, info *types.Info, stateExportImport string) bool {
	for index, left := range statement.Lhs {
		selector, ok := unparenthesized(left).(*ast.SelectorExpr)
		if !ok || !isStateExportTrustField(info.ObjectOf(selector.Sel), stateExportImport) {
			continue
		}
		// A tuple-producing right-hand side cannot be proved to assign nil to the
		// trust field, so the production guard fails closed.
		if index >= len(statement.Rhs) || len(statement.Rhs) != len(statement.Lhs) || !isNilExpression(statement.Rhs[index]) {
			return true
		}
	}
	return false
}

func stateExportConfigProvidesTrust(literal *ast.CompositeLit, info *types.Info, stateExportImport string) bool {
	structure, ok := stateExportConfigStruct(info.TypeOf(literal), stateExportImport)
	if !ok {
		return false
	}
	for index, element := range literal.Elts {
		if pair, keyed := element.(*ast.KeyValueExpr); keyed {
			identifier, identifierOK := unparenthesized(pair.Key).(*ast.Ident)
			if identifierOK && isStateExportTrustField(info.ObjectOf(identifier), stateExportImport) && !isNilExpression(pair.Value) {
				return true
			}
			continue
		}
		if index < structure.NumFields() && isStateExportTrustField(structure.Field(index), stateExportImport) && !isNilExpression(element) {
			return true
		}
	}
	return false
}

func stateExportNewServiceMayReceiveTrust(call *ast.CallExpr, info *types.Info, stateExportImport string) bool {
	function := calledFunction(call.Fun, info)
	if function == nil || function.Pkg() == nil || function.Pkg().Path() != stateExportImport || function.Name() != "NewService" || len(call.Args) == 0 {
		return false
	}
	argument := unparenthesized(call.Args[0])
	if !isStateExportConfigType(info.TypeOf(argument), stateExportImport) {
		return false
	}
	if literal, ok := argument.(*ast.CompositeLit); ok {
		return stateExportConfigProvidesTrust(literal, info, stateExportImport)
	}
	// Non-literal configuration flowing into the constructor can be populated
	// outside the call site. Require production composition to use an explicit
	// Config literal whose Signer and Verifier are absent or nil.
	return true
}

func stateExportConfigStruct(value types.Type, stateExportImport string) (*types.Struct, bool) {
	if value == nil {
		return nil, false
	}
	named, ok := types.Unalias(value).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != stateExportImport || named.Obj().Name() != "Config" {
		return nil, false
	}
	structure, ok := named.Underlying().(*types.Struct)
	return structure, ok
}

func isStateExportConfigType(value types.Type, stateExportImport string) bool {
	_, ok := stateExportConfigStruct(value, stateExportImport)
	return ok
}

func isStateExportTrustField(object types.Object, stateExportImport string) bool {
	field, ok := object.(*types.Var)
	return ok && field.IsField() && field.Pkg() != nil && field.Pkg().Path() == stateExportImport && (field.Name() == "Signer" || field.Name() == "Verifier")
}

func isNilExpression(expression ast.Expr) bool {
	identifier, ok := unparenthesized(expression).(*ast.Ident)
	return ok && identifier.Name == "nil"
}

func inspectReleaseNode(node ast.Node, info *types.Info, result *analysis) {
	call, ok := node.(*ast.CallExpr)
	if !ok {
		return
	}
	function := calledFunction(call.Fun, info)
	if function == nil || function.Pkg() == nil {
		return
	}
	path := function.Pkg().Path()
	name := function.Name()

	switch path {
	case "github.com/sigstore/sigstore-go/pkg/root":
		if strings.HasPrefix(name, "Fetch") || strings.HasPrefix(name, "NewLiveTrustedRoot") {
			result.ReleaseNetworkAccess = true
		}
	case "github.com/sigstore/sigstore-go/pkg/bundle":
		if name == "LoadJSONFromPath" {
			result.ReleaseArtifactExecution = true
		}
	case "github.com/sigstore/sigstore-go/pkg/verify":
		switch name {
		case "WithoutArtifactUnsafe":
			result.ReleaseArtifactExecution = true
		case "NewShortCertificateIdentity":
			if nonemptyStringArgument(call.Args, 1) || nonemptyStringArgument(call.Args, 3) {
				result.ReleaseArtifactExecution = true
			}
		case "NewSANMatcher", "NewIssuerMatcher":
			if nonemptyStringArgument(call.Args, 1) {
				result.ReleaseArtifactExecution = true
			}
		}
	case "os":
		if name == "StartProcess" {
			result.ReleaseArtifactExecution = true
		}
	case "syscall":
		if name == "Exec" || name == "ForkExec" || name == "StartProcess" {
			result.ReleaseArtifactExecution = true
		}
	}
}

func calledFunction(expression ast.Expr, info *types.Info) *types.Func {
	switch value := unparenthesized(expression).(type) {
	case *ast.Ident:
		function, _ := info.ObjectOf(value).(*types.Func)
		return function
	case *ast.SelectorExpr:
		function, _ := info.ObjectOf(value.Sel).(*types.Func)
		return function
	case *ast.IndexExpr:
		return calledFunction(value.X, info)
	case *ast.IndexListExpr:
		return calledFunction(value.X, info)
	default:
		return nil
	}
}

func nonemptyStringArgument(arguments []ast.Expr, index int) bool {
	if index >= len(arguments) {
		return true
	}
	literal, ok := unparenthesized(arguments[index]).(*ast.BasicLit)
	return !ok || literal.Kind != token.STRING || literal.Value != `""`
}

func functionRecognizesGeneratedCommands(function *ast.FuncDecl, info *types.Info, generatedImport string) bool {
	if function.Body == nil {
		return false
	}
	returned := make(map[types.Object]bool)
	ast.Inspect(function.Body, func(node ast.Node) bool {
		statement, ok := node.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for _, expression := range statement.Results {
			collectReferencedObjects(expression, info, returned)
		}
		return true
	})

	recognized := false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		statement, ok := node.(*ast.RangeStmt)
		if !ok {
			return true
		}
		selector, ok := unparenthesized(statement.X).(*ast.SelectorExpr)
		if !ok || !isGeneratedCommandsSelector(selector, info, generatedImport) {
			return true
		}
		value, ok := statement.Value.(*ast.Ident)
		if !ok || value.Name == "_" {
			return true
		}
		rangeObject := info.ObjectOf(value)
		if rangeObject == nil || !rangeBodyMatchesPath(statement.Body, rangeObject, info, generatedImport) {
			return true
		}
		if rangeBodyReturnsCommand(statement.Body, rangeObject, returned, info) {
			recognized = true
			return false
		}
		return true
	})
	return recognized
}

func rangeBodyMatchesPath(body *ast.BlockStmt, rangeObject types.Object, info *types.Info, generatedImport string) bool {
	matched := false
	ast.Inspect(body, func(node ast.Node) bool {
		var expressions []ast.Expr
		switch statement := node.(type) {
		case *ast.IfStmt:
			expressions = []ast.Expr{statement.Cond}
		case *ast.ForStmt:
			if statement.Cond != nil {
				expressions = []ast.Expr{statement.Cond}
			}
		case *ast.RangeStmt:
			expressions = []ast.Expr{statement.X}
		case *ast.SwitchStmt:
			if statement.Tag != nil {
				expressions = []ast.Expr{statement.Tag}
			}
		case *ast.CaseClause:
			expressions = statement.List
		}
		for _, expression := range expressions {
			if expressionUsesRangePath(expression, rangeObject, info, generatedImport) {
				matched = true
				return false
			}
		}
		return !matched
	})
	return matched
}

func expressionUsesRangePath(expression ast.Expr, rangeObject types.Object, info *types.Info, generatedImport string) bool {
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiver, ok := unparenthesized(selector.X).(*ast.Ident)
		field, fieldOK := info.Uses[selector.Sel].(*types.Var)
		if ok && fieldOK && info.ObjectOf(receiver) == rangeObject && field.IsField() && field.Name() == "Path" && field.Pkg() != nil && field.Pkg().Path() == generatedImport {
			found = true
			return false
		}
		return true
	})
	return found
}

func rangeBodyReturnsCommand(body *ast.BlockStmt, rangeObject types.Object, returned map[types.Object]bool, info *types.Info) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		switch statement := node.(type) {
		case *ast.ReturnStmt:
			for _, expression := range statement.Results {
				if expressionReferencesObject(expression, rangeObject, info) {
					found = true
					return false
				}
			}
		case *ast.AssignStmt:
			for index, right := range statement.Rhs {
				if index >= len(statement.Lhs) || !expressionReferencesObject(right, rangeObject, info) {
					continue
				}
				left, ok := statement.Lhs[index].(*ast.Ident)
				if ok && returned[info.ObjectOf(left)] {
					found = true
					return false
				}
			}
		}
		return !found
	})
	return found
}

func expressionReferencesObject(expression ast.Expr, target types.Object, info *types.Info) bool {
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok && info.ObjectOf(identifier) == target {
			found = true
			return false
		}
		return true
	})
	return found
}

func collectReferencedObjects(expression ast.Expr, info *types.Info, destination map[types.Object]bool) {
	ast.Inspect(expression, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok {
			if object := info.ObjectOf(identifier); object != nil {
				destination[object] = true
			}
		}
		return true
	})
}

func derivedCommandTypes(candidate checkedSourcePackage, generatedImport string) map[*types.Named]bool {
	derived := make(map[*types.Named]bool)
	var declarations []*ast.TypeSpec
	for _, file := range candidate.files {
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.TYPE {
				continue
			}
			for _, raw := range general.Specs {
				declarations = append(declarations, raw.(*ast.TypeSpec))
			}
		}
	}
	changed := true
	for changed {
		changed = false
		for _, declaration := range declarations {
			object := candidate.info.Defs[declaration.Name]
			if object == nil {
				continue
			}
			defined, ok := types.Unalias(object.Type()).(*types.Named)
			if !ok || derived[defined] {
				continue
			}
			context := analysisContext{generatedImport: generatedImport, derivedCommands: derived}
			if isCanonicalOrDerivedCommand(candidate.info.TypeOf(declaration.Type), context) {
				derived[defined] = true
				changed = true
			}
		}
	}
	return derived
}

func valueSpecIsRegistry(spec *ast.ValueSpec, info *types.Info, context analysisContext) bool {
	if spec.Type != nil && isDispatchCollection(info.TypeOf(spec.Type), context) {
		return true
	}
	for _, value := range spec.Values {
		if selector, ok := value.(*ast.SelectorExpr); ok && isGeneratedCommandsSelector(selector, info, context.generatedImport) {
			continue
		}
		if isDispatchCollection(info.TypeOf(value), context) {
			return true
		}
	}
	return false
}

func assignmentIsRegistry(statement *ast.AssignStmt, info *types.Info, context analysisContext) bool {
	for index, value := range statement.Rhs {
		if index < len(statement.Lhs) {
			if identifier, ok := statement.Lhs[index].(*ast.Ident); ok && identifier.Name == "_" {
				continue
			}
		}
		if selector, ok := value.(*ast.SelectorExpr); ok && isGeneratedCommandsSelector(selector, info, context.generatedImport) {
			continue
		}
		if isDispatchCollection(info.TypeOf(value), context) {
			return true
		}
	}
	return false
}

func isGeneratedCommandsSelector(selector *ast.SelectorExpr, info *types.Info, generatedImport string) bool {
	variable, ok := info.Uses[selector.Sel].(*types.Var)
	if !ok || variable.Name() != "Commands" || variable.Pkg() == nil || variable.Pkg().Path() != generatedImport {
		return false
	}
	return variable.Parent() == variable.Pkg().Scope() && variable.Pkg().Scope().Lookup("Commands") == variable
}

func unparenthesized(expression ast.Expr) ast.Expr {
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			return expression
		}
		expression = parenthesized.X
	}
}

func isDispatchCollection(value types.Type, context analysisContext) bool {
	if value == nil {
		return false
	}
	switch underlying := value.Underlying().(type) {
	case *types.Slice:
		return isDispatchEntry(underlying.Elem(), context)
	case *types.Array:
		return isDispatchEntry(underlying.Elem(), context)
	case *types.Map:
		return isString(underlying.Key()) && (isFunction(underlying.Elem()) || isDispatchEntry(underlying.Elem(), context))
	default:
		return false
	}
}

func isDispatchEntry(value types.Type, context analysisContext) bool {
	if isCanonicalOrDerivedCommand(value, context) {
		return true
	}
	value = unaliasPointers(value)
	if named, ok := types.Unalias(value).(*types.Named); ok {
		object := named.Obj()
		if object.Pkg() != nil && object.Pkg().Path() == context.generatedImport {
			// Generated non-command records, such as Flag, are authoritative
			// lookup data rather than parallel command registries.
			return false
		}
	}
	structure, ok := value.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	// Record collections block only on executable handlers or a bounded set of
	// route/action fields. Ordinary string-keyed record maps remain valid.
	for index := 0; index < structure.NumFields(); index++ {
		field := structure.Field(index)
		if isFunction(field.Type()) || isRouteField(field.Name()) {
			return true
		}
	}
	return false
}

func isCanonicalOrDerivedCommand(value types.Type, context analysisContext) bool {
	for {
		value = types.Unalias(value)
		if named, ok := value.(*types.Named); ok {
			if context.derivedCommands[named] {
				return true
			}
			object := named.Obj()
			return object.Pkg() != nil && object.Pkg().Path() == context.generatedImport && object.Name() == "Command"
		}
		pointer, ok := value.(*types.Pointer)
		if !ok {
			return false
		}
		value = pointer.Elem()
	}
}

func unaliasPointers(value types.Type) types.Type {
	for {
		value = types.Unalias(value)
		pointer, ok := value.(*types.Pointer)
		if !ok {
			return value
		}
		value = pointer.Elem()
	}
}

func isRouteField(name string) bool {
	switch strings.ToLower(name) {
	case "action", "actionid", "command", "commandname", "handler", "handlerid", "path", "route":
		return true
	default:
		return false
	}
}

func isString(value types.Type) bool {
	basic, ok := value.Underlying().(*types.Basic)
	return ok && basic.Kind() == types.String
}

func isFunction(value types.Type) bool {
	_, ok := value.Underlying().(*types.Signature)
	return ok
}
