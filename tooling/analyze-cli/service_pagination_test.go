package main

import (
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestServicePaginationTransportSealRemainsExact(t *testing.T) {
	raw, e := os.ReadFile(filepath.Join("..", "..", "internal", "localtransport", "transport.go"))
	if e != nil {
		t.Fatal(e)
	}
	imports := []string{"bytes", "context", "encoding/base64", "errors", "io", "net", "net/http", "net/url", "path", "strconv", "strings", "time", "github.com/vegastack/vegastack-labs/internal/credentialref"}
	api := []string{"ErrInvalid", "ErrRedirect", "ErrUnavailable", "Method", "MethodGet", "MethodPost", "Request", "Response", "RoundTrip", "StatusBadGateway", "StatusBadRequest", "StatusConflict", "StatusForbidden", "StatusNotFound", "StatusOK", "StatusPreconditionFailed", "StatusRequestTimeout", "StatusServiceUnavailable", "StatusUnauthorized"}
	for _, variant := range []string{"exact", "changed-source", "new-import", "missing-import", "renamed-file", "extra-file", "new-export"} {
		t.Run(variant, func(t *testing.T) {
			dir := t.TempDir()
			name := "transport.go"
			content := slices.Clone(raw)
			if variant == "changed-source" {
				content = append(content, []byte("\n// changed transport\n")...)
			}
			if variant == "renamed-file" {
				name = "other.go"
			}
			if e := os.WriteFile(filepath.Join(dir, name), content, 0600); e != nil {
				t.Fatal(e)
			}
			pkg := types.NewPackage("example.test/internal/localtransport", "localtransport")
			for _, name := range api {
				pkg.Scope().Insert(types.NewVar(token.NoPos, pkg, name, types.Typ[types.Invalid]))
			}
			c := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{Dir: dir, GoFiles: []string{name}, Imports: slices.Clone(imports)}}, typed: pkg}
			switch variant {
			case "new-import":
				c.listed.Imports = append(c.listed.Imports, "net/rpc")
			case "missing-import":
				c.listed.Imports = c.listed.Imports[1:]
			case "extra-file":
				c.listed.GoFiles = append(c.listed.GoFiles, "extra.go")
			case "new-export":
				pkg.Scope().Insert(types.NewVar(token.NoPos, pkg, "UnsafeURL", types.Typ[types.String]))
			}
			if got := reviewedLocalTransportPackage(c); got != (variant == "exact") {
				t.Fatalf("variant=%s allowed=%v", variant, got)
			}
		})
	}
}
