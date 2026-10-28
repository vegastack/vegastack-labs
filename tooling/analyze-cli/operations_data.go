package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Route-bearing delivery receipts and the fixed source-client map are data,
// not CLI dispatch registries. Admit only these exact source-owned AST sites.
func reviewedOperationsDataNode(c checkedSourcePackage, file *ast.File, node ast.Node, generatedImport string) bool {
	if c.listed.ImportPath != strings.TrimSuffix(generatedImport, "/internal/generated")+"/internal/server" {
		return false
	}
	names := append(append([]string(nil), c.listed.GoFiles...), c.listed.CgoFiles...)
	slices.Sort(names)
	name := ""
	for i, f := range c.files {
		if f == file && i < len(names) {
			name = names[i]
		}
	}
	function, source := "", ""
	var digests []string
	switch name {
	case "notification_readiness.go":
		function, source = "ExecuteBoundWithCredentials", "98b70f6cac731a8c62c8eae5e1eec8fec8e8bb99cd13ec6582ba19f63154c4b3"
		digests = []string{"032a83552e75e70b1b108a0d2e9b25b4a520308a028a20fafd483f63faccee2f", "61e2118b17cf9ff0a53e0270ba4a78a3f3a4c1396714b1d3eb36e807f140d5c6", "7620dce8cec108540fd7be5c94c3c45387838f64d4b4b2ff78cda601bc77c3ef", "7102565e3aecbe476bf8c0768c266d8df68d5827c27220828ae9fe2578bee488"}
	case "operations_monitoring.go":
		function, source = "registerOperationsMonitoring", "8a80da0e43fa1ecddba960a891fe5c9641e3d46fbd0cfabbe49c2d95334a981e"
		digests = []string{"17bdf87047a729f48bde132e352e3da75a1d23c6dfc772fe1c5a259a9308be41"}
	default:
		return false
	}
	raw, e := os.ReadFile(filepath.Join(c.listed.Dir, name))
	if e != nil || fmt.Sprintf("%x", sha256.Sum256(raw)) != source {
		return false
	}
	owned := false
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == function && fn.Body != nil {
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if n == node {
					owned = true
				}
				return !owned
			})
		}
	}
	if !owned {
		return false
	}
	var printed bytes.Buffer
	if format.Node(&printed, token.NewFileSet(), node) != nil {
		return false
	}
	return slices.Contains(digests, fmt.Sprintf("%x", sha256.Sum256(printed.Bytes())))
}
