package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRetainedAdministratorActualAccessSealsRejectDrift(t *testing.T) {
	const module = "github.com/vegastack/vegastack-labs"
	if len(retainedAdministratorSourceSeals) != 3 {
		t.Fatal("unexpected retained-administrator source scope")
	}
	current := retainedAdministratorSourceSeals
	if len(current) != 3 {
		t.Fatal("current variants widened")
	}
	for key, seal := range current {
		t.Run(key, func(t *testing.T) {
			relative, joined, ok := strings.Cut(key, "|")
			if !ok || relative != "internal/debianaccess" {
				t.Fatal("unexpected package authority")
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
			if !reviewedDebianAccessPackage(c, module, relative) || !reviewedDebianBaselinePackage(c, module, relative) || !approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("actual baseline checker rejected exact current source")
			}
			first := filepath.Join(dir, names[0])
			raw, e := os.ReadFile(first)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(first, append(slices.Clone(raw), []byte("\n// changed source\n")...), 0600); e != nil {
				t.Fatal(e)
			}
			if reviewedDebianAccessPackage(c, module, relative) || reviewedDebianBaselinePackage(c, module, relative) || approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("changed source inherited authority")
			}
			if e = os.WriteFile(first, raw, 0600); e != nil {
				t.Fatal(e)
			}
			c.listed.Imports = append(slices.Clone(seal.imports), "net/rpc")
			if reviewedDebianAccessPackage(c, module, relative) || reviewedDebianBaselinePackage(c, module, relative) || approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("extra import inherited authority")
			}
			c.listed.Imports = slices.Clone(seal.imports)
			c.listed.GoFiles = append(slices.Clone(names), "extra.go")
			if e = os.WriteFile(filepath.Join(dir, "extra.go"), []byte("package debianaccess\n"), 0600); e != nil {
				t.Fatal(e)
			}
			if reviewedDebianAccessPackage(c, module, relative) || reviewedDebianBaselinePackage(c, module, relative) || approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("extra file inherited authority")
			}
			c.listed.GoFiles = slices.Clone(names)
			c.listed.GoFiles[0] = "renamed.go"
			if e = os.WriteFile(filepath.Join(dir, "renamed.go"), raw, 0600); e != nil {
				t.Fatal(e)
			}
			if reviewedDebianAccessPackage(c, module, relative) || reviewedDebianBaselinePackage(c, module, relative) || approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("renamed file inherited authority")
			}
			c.listed.GoFiles = slices.Clone(names)
			c.listed.ImportPath = module + "/internal/sibling"
			if reviewedDebianAccessPackage(c, module, relative) || reviewedDebianBaselinePackage(c, module, relative) || approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("sibling package inherited authority")
			}
		})
	}
}
