package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestManualPublicationTypedSealsRejectDrift(t *testing.T) {
	const module = "github.com/vegastack/vegastack-labs"
	if len(manualPublicationSourceSeals) != 5 {
		t.Fatal("manual source scope widened")
	}
	for key, seal := range manualPublicationSourceSeals {
		t.Run(key, func(t *testing.T) {
			relative, joined, ok := strings.Cut(key, "|")
			if !ok || (relative != "internal/cli" && relative != "internal/localapi" && relative != "internal/serverconfig") {
				t.Fatal("unexpected manual package")
			}
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
			c := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{ImportPath: module + "/" + relative, Dir: dir, GoFiles: slices.Clone(names), Imports: slices.Clone(seal.imports)}}}
			if !approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("exact typed manual source denied")
			}
			if relative == "internal/cli" && !controllerPrerequisitePackage(c, module, relative) {
				t.Fatal("exact doctor composition denied")
			}
			first := filepath.Join(dir, names[0])
			raw, e := os.ReadFile(first)
			if e != nil {
				t.Fatal(e)
			}
			os.WriteFile(first, append(slices.Clone(raw), []byte("\n// changed source\n")...), 0600)
			if approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("changed source inherited authority")
			}
			os.WriteFile(first, raw, 0600)
			c.listed.Imports = append(slices.Clone(seal.imports), "net/rpc")
			if approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("extra import inherited authority")
			}
			c.listed.Imports = slices.Clone(seal.imports)
			c.listed.GoFiles = append(slices.Clone(names), "extra.go")
			os.WriteFile(filepath.Join(dir, "extra.go"), []byte("package arbitrary\n"), 0600)
			if approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("extra file inherited authority")
			}
			c.listed.GoFiles = slices.Clone(names)
			c.listed.ImportPath = module + "/internal/sibling"
			if approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("sibling inherited authority")
			}
		})
	}
}
