package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

func TestCIJobGrantPredicatesRequireExactFileLiteralAndFunction(t *testing.T) {
	const module = "github.com/vegastack/vegastack-labs"
	raw, e := os.ReadFile(filepath.Join("..", "..", "internal", "store", "ci_job_execution.go"))
	if e != nil {
		t.Fatal(e)
	}
	for _, variant := range []string{"exact", "changed", "sibling", "other-literal", "structure", "function"} {
		t.Run(variant, func(t *testing.T) {
			dir := t.TempDir()
			name := "ci_job_execution.go"
			if variant == "sibling" {
				name = "extra.go"
			}
			content := append([]byte(nil), raw...)
			if variant == "changed" {
				content = append(content, []byte("\n// changed predicates\n")...)
			}
			if os.WriteFile(filepath.Join(dir, name), content, 0600) != nil {
				t.Fatal("write")
			}
			file, e := parser.ParseFile(token.NewFileSet(), name, raw, 0)
			if e != nil {
				t.Fatal(e)
			}
			candidate := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{ImportPath: module + "/internal/store", Dir: dir, GoFiles: []string{name}}, files: []*ast.File{file}}}
			var literal *ast.CompositeLit
			var owner *ast.FuncDecl
			for _, d := range file.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || fn.Name.Name != "currentExecutionTx" {
					continue
				}
				owner = fn
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					r, ok := n.(*ast.RangeStmt)
					if ok {
						if x, ok := r.X.(*ast.CompositeLit); ok && len(x.Elts) == 2 {
							literal = x
						}
					}
					return true
				})
			}
			if literal == nil {
				t.Fatal("missing exact fixture")
			}
			switch variant {
			case "other-literal":
				literal = &ast.CompositeLit{Type: literal.Type, Elts: literal.Elts}
			case "structure":
				literal.Elts[0].(*ast.CompositeLit).Elts[1] = &ast.BasicLit{Kind: token.STRING, Value: "\"apply\""}
			case "function":
				owner.Name.Name = "otherExecution"
			}
			if got := reviewedCIJobGrantPredicates(candidate, file, literal, module+"/internal/generated"); got != (variant == "exact") {
				t.Fatalf("accepted=%v variant=%s", got, variant)
			}
		})
	}
}
