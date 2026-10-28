package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const controllerTestModule = "github.com/vegastack/vegastack-labs"

func controllerSealFixture(t *testing.T, key string, seal hostActionSourceSeal) listedPackage {
	t.Helper()
	relative, joined, _ := strings.Cut(key, "|")
	names := strings.Split(joined, ",")
	dir := t.TempDir()
	for _, name := range names {
		raw, e := os.ReadFile(filepath.Join("..", "..", relative, name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	return listedPackage{ImportPath: controllerTestModule + "/" + relative, Dir: dir, GoFiles: names, Imports: slices.Clone(seal.imports)}
}
func TestControllerCollectorAndEveryRoutingByteRequireExactSeals(t *testing.T) {
	var cli, collector listedPackage
	for key, seal := range controllerPrerequisiteSourceSeals {
		p := controllerSealFixture(t, key, seal)
		t.Run(key, func(t *testing.T) {
			relative, _, _ := strings.Cut(key, "|")
			if !controllerPrerequisitePackage(checkedSourcePackage{listed: p}, controllerTestModule, relative) {
				t.Fatal("exact source rejected")
			}
			if relative == "internal/cli" {
				cli = p
			} else if slices.Contains(p.GoFiles, "collect_linux.go") {
				collector = p
			}
			changed := p
			changed.Imports = append(slices.Clone(p.Imports), "net/http")
			if controllerPrerequisitePackage(checkedSourcePackage{listed: changed}, controllerTestModule, relative) {
				t.Fatal("import widening accepted")
			}
			changed = p
			changed.GoFiles = append(slices.Clone(p.GoFiles), "ordinary_route.go")
			if controllerPrerequisitePackage(checkedSourcePackage{listed: changed}, controllerTestModule, relative) {
				t.Fatal("new route source accepted")
			}
			raw, e := os.ReadFile(filepath.Join(p.Dir, p.GoFiles[0]))
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(p.Dir, p.GoFiles[0]), append(raw, []byte("\n// changed route\n")...), 0600); e != nil {
				t.Fatal(e)
			}
			if controllerPrerequisitePackage(checkedSourcePackage{listed: p}, controllerTestModule, relative) {
				t.Fatal("changed source accepted")
			}
			if e = os.WriteFile(filepath.Join(p.Dir, p.GoFiles[0]), raw, 0600); e != nil {
				t.Fatal(e)
			}
		})
	}
	packages := []listedPackage{cli, collector}
	if !controllerPrerequisiteComposition(packages, controllerTestModule) {
		t.Fatal("sealed composition rejected")
	}
	// An ordinary API client cannot inherit the fixed local command's capability.
	packages = append(packages, listedPackage{ImportPath: controllerTestModule + "/internal/localapi", Imports: []string{collector.ImportPath}})
	if controllerPrerequisiteComposition(packages, controllerTestModule) {
		t.Fatal("ordinary API route inherited collector authority")
	}
	packages = packages[:2]
	packages[0].GoFiles = append(slices.Clone(cli.GoFiles), "ordinary_route.go")
	if controllerPrerequisiteComposition(packages, controllerTestModule) {
		t.Fatal("new ordinary CLI route inherited local authority")
	}
}
func TestControllerFixedPathDataRequiresOwningAST(t *testing.T) {
	for key, seal := range controllerPrerequisiteSourceSeals {
		if !strings.HasPrefix(key, "internal/controllerprerequisites|") || !strings.Contains(key, "collect_posix.go") {
			continue
		}
		p := controllerSealFixture(t, key, seal)
		candidate := checkedSourcePackage{sourcePackage: sourcePackage{listed: p}}
		var file *ast.File
		var literal *ast.CompositeLit
		var owner *ast.FuncDecl
		for _, name := range p.GoFiles {
			f, e := parser.ParseFile(token.NewFileSet(), filepath.Join(p.Dir, name), nil, 0)
			if e != nil {
				t.Fatal(e)
			}
			candidate.files = append(candidate.files, f)
			if name == "collect_posix.go" {
				file = f
			}
		}
		for _, d := range file.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "collectRoot" {
				owner = fn
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if r, ok := n.(*ast.RangeStmt); ok {
						if l, ok := r.X.(*ast.CompositeLit); ok && len(l.Elts) == 7 {
							literal = l
						}
					}
					return true
				})
			}
		}
		generated := controllerTestModule + "/internal/generated"
		if literal == nil || !reviewedControllerPrerequisiteData(candidate, file, literal, generated) {
			t.Fatal("exact fixed path literal rejected")
		}
		copy := *literal
		if reviewedControllerPrerequisiteData(candidate, file, &copy, generated) {
			t.Fatal("borrowed AST inherited data allowance")
		}
		owner.Name.Name = "ordinaryDoctor"
		if reviewedControllerPrerequisiteData(candidate, file, literal, generated) {
			t.Fatal("other owning function accepted")
		}
	}
}
func TestOrdinaryClientServerPathDetectionRemainsActive(t *testing.T) {
	f, e := parser.ParseFile(token.NewFileSet(), "ordinary.go", `package client; func read(){ _ = "/var/lib/vsk-labs/control/control.db" }`, 0)
	if e != nil {
		t.Fatal(e)
	}
	c := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{ImportPath: controllerTestModule + "/internal/localapi"}, files: []*ast.File{f}, info: &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}}}
	var result analysis
	inspectPackage(c, controllerTestModule+"/internal/generated", controllerTestModule+"/internal/stateexport", false, false, true, &result)
	if !result.ControlServerPath {
		t.Fatal("ordinary client local database path escaped detection")
	}
	if controllerPrerequisitePackage(c, controllerTestModule, "internal/controllerprerequisites") {
		t.Fatal("ordinary client gained collector seal")
	}
}
