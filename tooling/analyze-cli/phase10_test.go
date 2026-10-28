package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestMaintenancePureValidatorPrunesOnlyExactSealedEdge(t *testing.T) {
	const module = "github.com/vegastack/vegastack-labs"
	var names, imports []string
	for key, seal := range phase10SourceSeals {
		if strings.HasPrefix(key, "internal/maintenance|") {
			names = strings.Split(strings.SplitN(key, "|", 2)[1], ",")
			imports = slices.Clone(seal.imports)
		}
	}
	if len(names) == 0 {
		t.Fatal("missing exact validator seal")
	}
	directory := t.TempDir()
	for _, name := range names {
		raw, e := os.ReadFile(filepath.Join("..", "..", "internal/maintenance", name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(directory, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	localAPI, validator, identity := module+"/internal/localapi", module+"/internal/maintenance", module+"/internal/debianaccess"
	packages := []listedPackage{{ImportPath: localAPI, Imports: []string{validator}}, {ImportPath: validator, Dir: directory, GoFiles: names, Imports: imports}, {ImportPath: identity}}
	check := func(packages []listedPackage) bool {
		pruning := phase10DependencyPruning(packages, module)
		closure := moduleDependencyClosurePruned(packages, localAPI, pruning)
		return reviewedLocalClientDependencies(closure, module, localAPI, module+"/internal/localtransport", module+"/internal/sshtransport", pruning)
	}
	if !check(packages) {
		t.Fatal("exact pure validator closure rejected")
	}
	packages[0].Imports = append(packages[0].Imports, identity)
	if check(packages) {
		t.Fatal("direct Debian access dependency inherited validator authority")
	}
	packages[0].Imports = []string{validator}
	packages[1].Imports = append(slices.Clone(imports), "net/http")
	if check(packages) {
		t.Fatal("new validator import inherited pure authority")
	}
	packages[1].Imports = imports
	packages[1].GoFiles = append(slices.Clone(names), "unapproved.go")
	if check(packages) {
		t.Fatal("new validator source file inherited pure authority")
	}
	packages[1].GoFiles = names
	file := filepath.Join(directory, names[0])
	raw, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(file, append(raw, []byte("\n// source changed\n")...), 0600); e != nil {
		t.Fatal(e)
	}
	if check(packages) {
		t.Fatal("changed validator source retained Debian access pruning")
	}
}
