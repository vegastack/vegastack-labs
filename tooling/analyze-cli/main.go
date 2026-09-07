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
	GeneratedCommandsReference bool     `json:"generatedCommandsReference"`
	HandwrittenRegistry        bool     `json:"handwrittenRegistry"`
	SQLiteAccess               bool     `json:"sqliteAccess"`
	ShellDispatch              bool     `json:"shellDispatch"`
	TargetsAnalyzed            []string `json:"targetsAnalyzed"`
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
	result.TargetsAnalyzed = []string{goos + "/" + goarch}
	return result, nil
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
		for _, imported := range candidate.Imports {
			if imported == "database/sql" {
				result.SQLiteAccess = true
			}
			if imported == "os/exec" {
				result.ShellDispatch = true
			}
		}
		inspectPackage(parsed, generatedImport, &result)
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

func inspectPackage(candidate checkedSourcePackage, generatedImport string, result *analysis) {
	context := analysisContext{
		generatedImport: generatedImport,
		derivedCommands: derivedCommandTypes(candidate, generatedImport),
	}
	for _, file := range candidate.files {
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.RangeStmt:
				if selector, ok := unparenthesized(typed.X).(*ast.SelectorExpr); ok && isGeneratedCommandsSelector(selector, candidate.info, generatedImport) {
					result.GeneratedCommandsReference = true
				}
			case *ast.ValueSpec:
				if candidate.listed.ImportPath != generatedImport && valueSpecIsRegistry(typed, candidate.info, context) {
					result.HandwrittenRegistry = true
				}
			case *ast.AssignStmt:
				if candidate.listed.ImportPath != generatedImport && assignmentIsRegistry(typed, candidate.info, context) {
					result.HandwrittenRegistry = true
				}
			case *ast.CompositeLit:
				if candidate.listed.ImportPath != generatedImport && isDispatchCollection(candidate.info.TypeOf(typed), context) {
					result.HandwrittenRegistry = true
				}
			}
			return true
		})
	}
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
		return isDispatchEntry(underlying.Elem(), context, true)
	case *types.Array:
		return isDispatchEntry(underlying.Elem(), context, true)
	case *types.Map:
		return isString(underlying.Key()) && (isFunction(underlying.Elem()) || isDispatchEntry(underlying.Elem(), context, false))
	default:
		return false
	}
}

func isDispatchEntry(value types.Type, context analysisContext, requireRouteSemantics bool) bool {
	for {
		pointer, ok := value.(*types.Pointer)
		if !ok {
			break
		}
		value = pointer.Elem()
	}
	if isCanonicalOrDerivedCommand(value, context) {
		return true
	}
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
	if !requireRouteSemantics {
		return true
	}
	for index := 0; index < structure.NumFields(); index++ {
		field := structure.Field(index)
		if isFunction(field.Type()) || isRouteField(field.Name()) {
			return true
		}
	}
	return false
}

func isCanonicalOrDerivedCommand(value types.Type, context analysisContext) bool {
	value = types.Unalias(value)
	named, ok := value.(*types.Named)
	if !ok {
		return false
	}
	if context.derivedCommands[named] {
		return true
	}
	object := named.Obj()
	return object.Pkg() != nil && object.Pkg().Path() == context.generatedImport && object.Name() == "Command"
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
