package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestHostWorkflowClientSealRejectsDrift(t *testing.T) {
	const module = "github.com/vegastack/vegastack-labs"
	checked := 0
	for key, seal := range phase228SourceSeals {
		relative, joined, _ := strings.Cut(key, "|")
		if relative != "internal/localapi" || !strings.Contains(joined, "authorization_grants.go") {
			continue
		}
		names := strings.Split(joined, ",")
		dir := t.TempDir()
		for _, name := range names {
			b, e := os.ReadFile(filepath.Join("..", "..", relative, name))
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
				t.Fatal(e)
			}
		}
		c := checkedSourcePackage{}
		c.listed.Dir = dir
		c.listed.ImportPath = module + "/" + relative
		c.listed.GoFiles = names
		c.listed.Imports = slices.Clone(seal.imports)
		if !reviewedLocalAPISource(c) {
			t.Fatal("current finite source closure rejected")
		}
		c.listed.Imports = append(c.listed.Imports, "net/rpc")
		if reviewedLocalAPISource(c) {
			t.Fatal("widened imports accepted")
		}
		c.listed.Imports = slices.Clone(seal.imports)
		p := filepath.Join(dir, names[0])
		f, e := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		_, _ = f.WriteString("\n// unreviewed source mutation\n")
		_ = f.Close()
		if reviewedLocalAPISource(c) {
			t.Fatal("changed source accepted")
		}
		checked++
	}
	if checked < 2 {
		t.Fatal("Linux and unsupported closures must both be sealed")
	}
}
