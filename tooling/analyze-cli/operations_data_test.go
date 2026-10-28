package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

func TestOperationsDataAllowanceRequiresExactSourceOwnerAndAST(t *testing.T) {
	const generated = "github.com/vegastack/vegastack-labs/internal/generated"
	for _, name := range []string{"notification_readiness.go", "operations_monitoring.go"} {
		raw, e := os.ReadFile(filepath.Join("..", "..", "internal", "server", name))
		if e != nil {
			t.Fatal(e)
		}
		for _, variant := range []string{"exact", "changed", "sibling", "function", "other-node", "structure", "package"} {
			t.Run(name+"/"+variant, func(t *testing.T) {
				dir := t.TempDir()
				filename := name
				if variant == "sibling" {
					filename = "extra.go"
				}
				content := append([]byte(nil), raw...)
				if variant == "changed" {
					content = append(content, []byte("\n// drift\n")...)
				}
				if e := os.WriteFile(filepath.Join(dir, filename), content, 0600); e != nil {
					t.Fatal(e)
				}
				file, e := parser.ParseFile(token.NewFileSet(), filename, raw, 0)
				if e != nil {
					t.Fatal(e)
				}
				c := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{ImportPath: "github.com/vegastack/vegastack-labs/internal/server", Dir: dir, GoFiles: []string{filename}}, files: []*ast.File{file}}}
				// Find only the exact sites accepted in the unmodified owning AST.
				probe := c
				probe.listed.Dir = filepath.Join("..", "..", "internal", "server")
				probe.listed.GoFiles = []string{name}
				var nodes []ast.Node
				ast.Inspect(file, func(n ast.Node) bool {
					switch n.(type) {
					case *ast.AssignStmt, *ast.CompositeLit:
						if reviewedOperationsDataNode(probe, file, n, generated) {
							nodes = append(nodes, n)
						}
					}
					return true
				})
				want := 5
				if name == "operations_monitoring.go" {
					want = 1
				}
				if len(nodes) != want {
					t.Fatalf("sites=%d want=%d", len(nodes), want)
				}
				if variant == "function" {
					for _, d := range file.Decls {
						if fn, ok := d.(*ast.FuncDecl); ok {
							fn.Name.Name = "other"
						}
					}
				}
				if variant == "package" {
					c.listed.ImportPath = "example.test/internal/server"
				}
				for _, original := range nodes {
					node := original
					switch variant {
					case "other-node":
						switch n := original.(type) {
						case *ast.AssignStmt:
							copy := *n
							node = &copy
						case *ast.CompositeLit:
							copy := *n
							node = &copy
						}
					case "structure":
						switch n := original.(type) {
						case *ast.AssignStmt:
							n.Lhs = []ast.Expr{ast.NewIdent("routes")}
						case *ast.CompositeLit:
							n.Elts = append(n.Elts, ast.NewIdent("extra"))
						}
					}
					if got := reviewedOperationsDataNode(c, file, node, generated); got != (variant == "exact") {
						t.Fatalf("allowed=%v variant=%s node=%T", got, variant, node)
					}
				}
			})
		}
	}
}
