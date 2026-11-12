package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestConsoleStatusClientSealsRejectDrift(t *testing.T) {
	const module = "github.com/vegastack/vegastack-labs"
	if len(consoleStatusClientSourceSeals) != 2 {
		t.Fatal("unexpected client variant scope")
	}
	for key, seal := range consoleStatusClientSourceSeals {
		t.Run(key, func(t *testing.T) {
			relative, joined, ok := strings.Cut(key, "|")
			if !ok || relative != "internal/localapi" {
				t.Fatal("unexpected package")
			}
			names := strings.Split(joined, ",")
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
			if !reviewedLocalAPISource(c) {
				t.Fatal("current client rejected")
			}
			file := filepath.Join(dir, "client.go")
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(file, append(slices.Clone(raw), []byte("\n// unreviewed drift\n")...), 0600); err != nil {
				t.Fatal(err)
			}
			if reviewedLocalAPISource(c) {
				t.Fatal("changed source inherited client authority")
			}
			if err = os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			c.listed.Imports = append(slices.Clone(seal.imports), "net/rpc")
			if reviewedLocalAPISource(c) {
				t.Fatal("extra import inherited client authority")
			}
			c.listed.Imports = slices.Clone(seal.imports)
			c.listed.GoFiles = append(slices.Clone(names), "extra.go")
			if err = os.WriteFile(filepath.Join(dir, "extra.go"), []byte("package localapi\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if reviewedLocalAPISource(c) {
				t.Fatal("extra source inherited client authority")
			}
		})
	}
}
