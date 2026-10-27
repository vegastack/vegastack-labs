package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCIEnrollmentClientSourceSealsRejectChangedSourceAndSiblings(t *testing.T) {
	const module = "github.com/vegastack/vegastack-labs"
	for key, seal := range ciEnrollmentSourceSeals {
		t.Run(key, func(t *testing.T) {
			parts := strings.SplitN(key, "|", 2)
			relative, names := parts[0], strings.Split(parts[1], ",")
			dir := t.TempDir()
			for _, name := range names {
				raw, err := os.ReadFile(filepath.Join("..", "..", relative, name))
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			c := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{ImportPath: module + "/" + relative, Dir: dir, GoFiles: slices.Clone(names), Imports: slices.Clone(seal.imports)}}}
			if !approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("exact enrollment source variant denied")
			}
			first := filepath.Join(dir, names[0])
			raw, err := os.ReadFile(first)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(first, append(slices.Clone(raw), []byte("\n// changed source\n")...), 0600); err != nil {
				t.Fatal(err)
			}
			if approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("changed enrollment source inherited authority")
			}
			if err = os.WriteFile(first, raw, 0600); err != nil {
				t.Fatal(err)
			}
			c.listed.GoFiles = append(c.listed.GoFiles, "extra.go")
			if err = os.WriteFile(filepath.Join(dir, "extra.go"), []byte("package extra\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("sibling source inherited authority")
			}
			c.listed.GoFiles = slices.Clone(names)
			c.listed.Imports = append(c.listed.Imports, "net/http")
			if approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("new import inherited authority")
			}
		})
	}
}
