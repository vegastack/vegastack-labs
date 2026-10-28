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

// Blob.Open reopens already frozen, digest-checked artifact bytes. These three
// exact assignments copy artifact data; they do not register commands. Bind
// source bytes, package/file, owning function AND assignment AST independently.
func reviewedCIBlobDataCopy(c checkedSourcePackage, file *ast.File, statement *ast.AssignStmt, generatedImport string) bool {
	module := strings.TrimSuffix(generatedImport, "/internal/generated")
	names := append(append([]string(nil), c.listed.GoFiles...), c.listed.CgoFiles...)
	slices.Sort(names)
	name := ""
	for i, f := range c.files {
		if f == file && i < len(names) {
			name = names[i]
		}
	}
	for _, seal := range []struct{ relative, function, source, statement string }{
		{"internal/adapter/ociregistry/client.go", "Publish", "5819cf59bbb742f187dafa6634319ad50a5b79c6fee1cce6c2bf874a470b3761", "43a497db21ecb74ba5e1a2e6f4b67aba30f0b061c90702a7006b6708a89a275b"},
		{"internal/adapter/ociregistry/verified.go", "PublishVerified", "6d5e2fb99ebebbf05dd92f0036f893224ae0193ed8efadbfa9e477165ee4227e", "df5f3fa581055fb6b6d2f676801247f110cd9835b072c6993115ea12cd285994"},
		{"internal/server/ci_publication.go", "candidate", "2cd38e8511183aa040d2d896d70c8ae2d15c12a9a1742fc8e1b952f6cce92478", "f0c43368cf19f6c39e807e7b5769b5cc52357558be2fca12439c5db4d5eef8c4"},
	} {
		if name != filepath.Base(seal.relative) || c.listed.ImportPath != module+"/"+filepath.ToSlash(filepath.Dir(seal.relative)) {
			continue
		}
		raw, e := os.ReadFile(filepath.Join(c.listed.Dir, name))
		if e != nil || fmt.Sprintf("%x", sha256.Sum256(raw)) != seal.source {
			return false
		}
		owned := false
		for _, d := range file.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == seal.function && fn.Pos() <= statement.Pos() && statement.End() <= fn.End() {
				owned = true
			}
		}
		if !owned {
			return false
		}
		var printed bytes.Buffer
		if format.Node(&printed, token.NewFileSet(), statement) != nil {
			return false
		}
		return fmt.Sprintf("%x", sha256.Sum256(printed.Bytes())) == seal.statement
	}
	return false
}
