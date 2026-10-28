package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

func TestCIBlobCopyRequiresExactSourceOwnerAndStatement(t *testing.T) {
	const module = "github.com/vegastack/vegastack-labs"
	for _, relative := range []string{"internal/adapter/ociregistry/client.go", "internal/adapter/ociregistry/verified.go", "internal/server/ci_publication.go"} {
		raw, e := os.ReadFile(filepath.Join("..", "..", relative))
		if e != nil {
			t.Fatal(e)
		}
		for _, variant := range []string{"exact", "changed", "sibling", "renamed-package", "function", "statement"} {
			t.Run(relative+"/"+variant, func(t *testing.T) {
				dir := t.TempDir()
				name := filepath.Base(relative)
				content := append([]byte(nil), raw...)
				if variant == "changed" {
					content = append(content, []byte("\n// changed artifact source\n")...)
				}
				if variant == "sibling" {
					name = "renamed.go"
				}
				if os.WriteFile(filepath.Join(dir, name), content, 0600) != nil {
					t.Fatal("write fixture")
				}
				f, e := parser.ParseFile(token.NewFileSet(), name, raw, 0)
				if e != nil {
					t.Fatal(e)
				}
				c := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{ImportPath: module + "/" + filepath.ToSlash(filepath.Dir(relative)), Dir: dir, GoFiles: []string{name}}, files: []*ast.File{f}}}
				if variant == "renamed-package" {
					c.listed.ImportPath = module + "/internal/sibling"
				}
				var statement *ast.AssignStmt
				var owner *ast.FuncDecl
				for _, d := range f.Decls {
					fn, ok := d.(*ast.FuncDecl)
					if !ok {
						continue
					}
					ast.Inspect(fn, func(n ast.Node) bool {
						a, ok := n.(*ast.AssignStmt)
						if !ok || len(a.Lhs) != 1 {
							return true
						}
						sel, ok := a.Lhs[0].(*ast.SelectorExpr)
						if ok && sel.Sel.Name == "Blobs" {
							statement = a
							owner = fn
						}
						return true
					})
				}
				if statement == nil {
					t.Fatal("blob assignment missing")
				}
				if variant == "function" {
					owner.Name.Name = "registerCommands"
				}
				if variant == "statement" {
					statement.Lhs[0].(*ast.SelectorExpr).Sel.Name = "Commands"
				}
				if got := reviewedCIBlobDataCopy(c, f, statement, module+"/internal/generated"); got != (variant == "exact") {
					t.Fatalf("variant=%s allowed=%v", variant, got)
				}
			})
		}
	}
}
