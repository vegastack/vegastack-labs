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

var targets = [][2]string{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
	{"windows", "amd64"},
}

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
	Module     *module
}

type analysis struct {
	GeneratedCommandsReference bool `json:"generatedCommandsReference"`
	HandwrittenRegistry        bool `json:"handwrittenRegistry"`
	SQLiteAccess               bool `json:"sqliteAccess"`
	ShellDispatch              bool `json:"shellDispatch"`
}

type sourcePackage struct {
	listed listedPackage
	files  []*ast.File
	info   *types.Info
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
	flag.Parse()
	if *root == "" {
		fmt.Fprintln(os.Stderr, "analyze-cli: --root is required")
		os.Exit(2)
	}

	result, err := analyze(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyze-cli: %v\n", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "analyze-cli: encode result: %v\n", err)
		os.Exit(1)
	}
}

func analyze(root string) (analysis, error) {
	var combined analysis
	for _, target := range targets {
		packages, err := listPackages(root, target[0], target[1])
		if err != nil {
			return analysis{}, fmt.Errorf("list %s/%s dependency closure: %w", target[0], target[1], err)
		}
		result, err := analyzeTarget(packages)
		if err != nil {
			return analysis{}, fmt.Errorf("analyze %s/%s dependency closure: %w", target[0], target[1], err)
		}
		if !result.GeneratedCommandsReference {
			return analysis{}, fmt.Errorf("%s/%s runtime does not reference generated.Commands", target[0], target[1])
		}
		combined.GeneratedCommandsReference = true
		combined.HandwrittenRegistry = combined.HandwrittenRegistry || result.HandwrittenRegistry
		combined.SQLiteAccess = combined.SQLiteAccess || result.SQLiteAccess
		combined.ShellDispatch = combined.ShellDispatch || result.ShellDispatch
	}
	return combined, nil
}

func listPackages(root, goos, goarch string) ([]listedPackage, error) {
	command := exec.Command("go", "list", "-deps", "-json", "./cmd/vsk-labs")
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
	for _, candidate := range listed {
		if candidate.Module != nil && candidate.Module.Path != "" {
			modulePath = candidate.Module.Path
			break
		}
	}
	if modulePath == "" {
		return analysis{}, errors.New("main module path is unavailable")
	}
	mainImport := modulePath + "/cmd/vsk-labs"
	generatedImport := modulePath + "/internal/generated"
	if !containsPackage(listed, mainImport) || !containsPackage(listed, generatedImport) {
		return analysis{}, errors.New("runtime dependency closure omits the executable or generated package")
	}

	checked := make(map[string]*types.Package)
	loader := packageImporter{checked: checked, fallback: importer.Default()}
	var result analysis
	for _, candidate := range listed {
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
	for _, file := range candidate.files {
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.SelectorExpr:
				if isGeneratedCommandsSelector(typed, candidate.info, generatedImport) {
					result.GeneratedCommandsReference = true
				}
			case *ast.ValueSpec:
				if candidate.listed.ImportPath != generatedImport && valueSpecIsRegistry(typed, candidate.info, generatedImport) {
					result.HandwrittenRegistry = true
				}
			case *ast.AssignStmt:
				if candidate.listed.ImportPath != generatedImport && assignmentIsRegistry(typed, candidate.info, generatedImport) {
					result.HandwrittenRegistry = true
				}
			case *ast.CompositeLit:
				if candidate.listed.ImportPath != generatedImport && isDispatchCollection(candidate.info.TypeOf(typed), generatedImport) {
					result.HandwrittenRegistry = true
				}
			}
			return true
		})
	}
}

func valueSpecIsRegistry(spec *ast.ValueSpec, info *types.Info, generatedImport string) bool {
	if spec.Type != nil && isDispatchCollection(info.TypeOf(spec.Type), generatedImport) {
		return true
	}
	for _, value := range spec.Values {
		if selector, ok := value.(*ast.SelectorExpr); ok && isGeneratedCommandsSelector(selector, info, generatedImport) {
			continue
		}
		if isDispatchCollection(info.TypeOf(value), generatedImport) {
			return true
		}
	}
	return false
}

func assignmentIsRegistry(statement *ast.AssignStmt, info *types.Info, generatedImport string) bool {
	for index, value := range statement.Rhs {
		if index < len(statement.Lhs) {
			if identifier, ok := statement.Lhs[index].(*ast.Ident); ok && identifier.Name == "_" {
				continue
			}
		}
		if selector, ok := value.(*ast.SelectorExpr); ok && isGeneratedCommandsSelector(selector, info, generatedImport) {
			continue
		}
		if isDispatchCollection(info.TypeOf(value), generatedImport) {
			return true
		}
	}
	return false
}

func isGeneratedCommandsSelector(selector *ast.SelectorExpr, info *types.Info, generatedImport string) bool {
	object := info.Uses[selector.Sel]
	return object != nil && object.Name() == "Commands" && object.Pkg() != nil && object.Pkg().Path() == generatedImport
}

func isDispatchCollection(value types.Type, generatedImport string) bool {
	if value == nil {
		return false
	}
	switch underlying := value.Underlying().(type) {
	case *types.Slice:
		return isDispatchEntry(underlying.Elem(), generatedImport)
	case *types.Array:
		return isDispatchEntry(underlying.Elem(), generatedImport)
	case *types.Map:
		return isString(underlying.Key()) && (isFunction(underlying.Elem()) || isDispatchEntry(underlying.Elem(), generatedImport))
	default:
		return false
	}
}

func isDispatchEntry(value types.Type, generatedImport string) bool {
	for {
		pointer, ok := value.(*types.Pointer)
		if !ok {
			break
		}
		value = pointer.Elem()
	}
	if named, ok := value.(*types.Named); ok {
		object := named.Obj()
		if object.Pkg() != nil && object.Pkg().Path() == generatedImport && object.Name() == "Command" {
			return true
		}
	}
	structure, ok := value.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for index := 0; index < structure.NumFields(); index++ {
		if isFunction(structure.Field(index).Type()) {
			return true
		}
	}
	return false
}

func isString(value types.Type) bool {
	basic, ok := value.Underlying().(*types.Basic)
	return ok && basic.Kind() == types.String
}

func isFunction(value types.Type) bool {
	_, ok := value.Underlying().(*types.Signature)
	return ok
}
