package credentialref_test

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
)

var allowedCredentialAPI = []string{
	`const Current State = "current"`,
	`const Revoked State = "revoked"`,
	`const Stale State = "stale"`,
	`const Unavailable State = "unavailable"`,
	`field Error.Code string`,
	`field Error.Target string`,
	`field Metadata.MaterialVersion string`,
	`field Metadata.Reference Reference`,
	`field Metadata.State State`,
	`field Reference.Consumer string`,
	`field Reference.ID string`,
	`func Verify func(context.Context, Inspector, Reference, string) (Metadata, error)`,
	`method Error.Error func() (string)`,
	`method Inspector.Inspect func(context.Context, Reference) (Metadata, error)`,
	`type Error struct`,
	`type Inspector interface`,
	`type Metadata struct`,
	`type Reference struct`,
	`type State string`,
}

func TestCredentialReferenceExportedAPIIsMetadataOnly(t *testing.T) {
	fset, files := parseCredentialPackage(t)
	if issues := validateCredentialAPI(fset, files); len(issues) != 0 {
		t.Fatalf("credential-reference API changed:\n%s", strings.Join(issues, "\n"))
	}
}

func TestCredentialReferenceAPIGuardRejectsMaterialAndRevealSurfaces(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate credential-reference test source")
	}
	productionPath := filepath.Join(filepath.Dir(sourceFile), "reference.go")
	production, err := os.ReadFile(productionPath)
	if err != nil {
		t.Fatalf("read production source: %v", err)
	}

	fixture := strings.Replace(
		string(production),
		"type Reference struct {",
		"type Reference struct {\n\tMaterial []byte",
		1,
	)
	if fixture == string(production) {
		t.Fatal("adversarial fixture did not add a Material field")
	}
	fixture += "\nfunc (Reference) Reveal() []byte { return nil }\n"

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "adversarial_reference.go", fixture, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse adversarial fixture: %v", err)
	}
	issues := validateCredentialAPI(fset, []*ast.File{file})
	want := []string{
		"unexpected field Reference.Material []byte",
		"unexpected method Reference.Reveal func() ([]byte)",
	}
	if !slices.Equal(issues, want) {
		t.Fatalf("adversarial API issues = %#v, want %#v", issues, want)
	}
}

func parseCredentialPackage(t *testing.T) (*token.FileSet, []*ast.File) {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate credential-reference test source")
	}
	directory := filepath.Dir(sourceFile)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read credential-reference package: %v", err)
	}

	fset := token.NewFileSet()
	var files []*ast.File
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		file, parseErr := parser.ParseFile(fset, path, nil, parser.AllErrors)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", entry.Name(), parseErr)
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		t.Fatal("credential-reference package has no production Go files")
	}
	return fset, files
}

func validateCredentialAPI(fset *token.FileSet, files []*ast.File) []string {
	actual := exportedSurface(fset, files)
	expected := make(map[string]struct{}, len(allowedCredentialAPI))
	for _, item := range allowedCredentialAPI {
		expected[item] = struct{}{}
	}

	var issues []string
	for item := range actual {
		if _, ok := expected[item]; !ok {
			issues = append(issues, "unexpected "+item)
		}
	}
	for item := range expected {
		if _, ok := actual[item]; !ok {
			issues = append(issues, "missing "+item)
		}
	}
	sort.Strings(issues)
	return issues
}

func exportedSurface(fset *token.FileSet, files []*ast.File) map[string]struct{} {
	surface := make(map[string]struct{})
	for _, file := range files {
		for _, declaration := range file.Decls {
			switch declaration := declaration.(type) {
			case *ast.GenDecl:
				collectGeneralDeclaration(fset, surface, declaration)
			case *ast.FuncDecl:
				if !ast.IsExported(declaration.Name.Name) {
					continue
				}
				kind := "func "
				name := declaration.Name.Name
				if declaration.Recv != nil && len(declaration.Recv.List) > 0 {
					kind = "method "
					name = receiverName(declaration.Recv.List[0].Type) + "." + name
				}
				surface[kind+name+" "+functionSignature(fset, declaration.Type)] = struct{}{}
			}
		}
	}
	return surface
}

func collectGeneralDeclaration(fset *token.FileSet, surface map[string]struct{}, declaration *ast.GenDecl) {
	for _, specification := range declaration.Specs {
		switch specification := specification.(type) {
		case *ast.TypeSpec:
			if !ast.IsExported(specification.Name.Name) {
				continue
			}
			name := specification.Name.Name
			surface[typeDescription(fset, specification)] = struct{}{}
			switch shape := specification.Type.(type) {
			case *ast.StructType:
				collectStructFields(fset, surface, name, shape)
			case *ast.InterfaceType:
				collectInterfaceMethods(fset, surface, name, shape)
			}
		case *ast.ValueSpec:
			collectExportedValues(fset, surface, declaration.Tok, specification)
		}
	}
}

func typeDescription(fset *token.FileSet, specification *ast.TypeSpec) string {
	prefix := "type " + specification.Name.Name + " "
	if specification.Assign.IsValid() {
		prefix += "= "
	}
	switch specification.Type.(type) {
	case *ast.StructType:
		return prefix + "struct"
	case *ast.InterfaceType:
		return prefix + "interface"
	default:
		return prefix + renderNode(fset, specification.Type)
	}
}

func collectStructFields(fset *token.FileSet, surface map[string]struct{}, owner string, structure *ast.StructType) {
	for _, field := range structure.Fields.List {
		if len(field.Names) == 0 {
			surface["embedded-field "+owner+"."+renderNode(fset, field.Type)] = struct{}{}
			continue
		}
		for _, name := range field.Names {
			if ast.IsExported(name.Name) {
				surface["field "+owner+"."+name.Name+" "+renderNode(fset, field.Type)] = struct{}{}
			}
		}
	}
}

func collectInterfaceMethods(fset *token.FileSet, surface map[string]struct{}, owner string, iface *ast.InterfaceType) {
	for _, field := range iface.Methods.List {
		if len(field.Names) == 0 {
			surface["interface-embed "+owner+"."+renderNode(fset, field.Type)] = struct{}{}
			continue
		}
		for _, name := range field.Names {
			if !ast.IsExported(name.Name) {
				continue
			}
			method, ok := field.Type.(*ast.FuncType)
			if !ok {
				surface["method "+owner+"."+name.Name+" "+renderNode(fset, field.Type)] = struct{}{}
				continue
			}
			surface["method "+owner+"."+name.Name+" "+functionSignature(fset, method)] = struct{}{}
		}
	}
}

func collectExportedValues(fset *token.FileSet, surface map[string]struct{}, tokenKind token.Token, specification *ast.ValueSpec) {
	for index, name := range specification.Names {
		if !ast.IsExported(name.Name) {
			continue
		}
		description := strings.ToLower(tokenKind.String()) + " " + name.Name
		if specification.Type != nil {
			description += " " + renderNode(fset, specification.Type)
		}
		if index < len(specification.Values) {
			description += " = " + renderNode(fset, specification.Values[index])
		}
		surface[description] = struct{}{}
	}
}

func functionSignature(fset *token.FileSet, function *ast.FuncType) string {
	parameters := fieldListTypes(fset, function.Params)
	results := fieldListTypes(fset, function.Results)
	signature := "func(" + strings.Join(parameters, ", ") + ")"
	if len(results) > 0 {
		signature += " (" + strings.Join(results, ", ") + ")"
	}
	return signature
}

func fieldListTypes(fset *token.FileSet, fields *ast.FieldList) []string {
	if fields == nil {
		return nil
	}
	var types []string
	for _, field := range fields.List {
		count := len(field.Names)
		if count == 0 {
			count = 1
		}
		for range count {
			types = append(types, renderNode(fset, field.Type))
		}
	}
	return types
}

func receiverName(expression ast.Expr) string {
	switch expression := expression.(type) {
	case *ast.Ident:
		return expression.Name
	case *ast.StarExpr:
		return receiverName(expression.X)
	case *ast.IndexExpr:
		return receiverName(expression.X)
	case *ast.IndexListExpr:
		return receiverName(expression.X)
	default:
		return "<unknown>"
	}
}

func renderNode(fset *token.FileSet, node any) string {
	var output bytes.Buffer
	if err := format.Node(&output, fset, node); err != nil {
		return fmt.Sprintf("<unrenderable:%T>", node)
	}
	return output.String()
}
