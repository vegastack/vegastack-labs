// Command analyze-cli performs the AST and type-based source checks used by
// tooling/verify-cli.mjs. It is development tooling and is not shipped.
package main

import (
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
	localAPIImport := modulePath + "/internal/localapi"
	cliImport := modulePath + "/internal/cli"
	clientFileImport := modulePath + "/internal/clientfile"
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
	for _, candidate := range inModule {
		parsed, err := parseAndCheck(candidate, loader)
		if err != nil {
			return analysis{}, err
		}
		checked[candidate.ImportPath] = parsed.infoPackage()
		isReleasePackage := candidate.ImportPath == releaseImport || strings.HasPrefix(candidate.ImportPath, releaseImport+"/")
		isControlPackage := candidate.ImportPath == cliImport || strings.HasPrefix(candidate.ImportPath, cliImport+"/") || candidate.ImportPath == clientFileImport || strings.HasPrefix(candidate.ImportPath, clientFileImport+"/")
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
				switch imported {
				case "net", "net/http", "github.com/sigstore/sigstore-go/pkg/tuf":
					result.ReleaseNetworkAccess = true
				case "os/exec", "plugin":
					result.ReleaseArtifactExecution = true
				}
			}
			if isControlPackage {
				switch imported {
				case "database/sql", "github.com/ncruces/go-sqlite3", "github.com/ncruces/go-sqlite3/driver":
					result.ControlSQLiteAccess = true
				case "os/exec", "plugin":
					result.ControlShellDispatch = true
				case "net/http":
					result.ControlArbitraryHTTP = true
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
		inspectPackage(parsed, generatedImport, stateExportImport, isReleasePackage, candidate.ImportPath == apiImport || candidate.ImportPath == localAPIImport, isControlPackage, &result)
	}
	return result, nil
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
