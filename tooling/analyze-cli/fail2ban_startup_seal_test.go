package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestFail2banJournalActualBaselineSealsRejectDrift(t *testing.T) {
	const module = "github.com/vegastack/vegastack-labs"
	if len(fail2banJournalSourceSeals) != 3 {
		t.Fatal("unexpected journal source scope")
	}
	for key, seal := range fail2banJournalSourceSeals {
		t.Run(key, func(t *testing.T) {
			relative, joined, ok := strings.Cut(key, "|")
			if !ok || relative != "internal/debianbaseline" {
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
			if !reviewedDebianBaselinePackage(c, module, relative) {
				t.Fatal("actual baseline checker rejected exact journal source")
			}
			first := filepath.Join(dir, names[0])
			raw, e := os.ReadFile(first)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(first, append(slices.Clone(raw), []byte("\n// changed source\n")...), 0600); e != nil {
				t.Fatal(e)
			}
			if reviewedDebianBaselinePackage(c, module, relative) {
				t.Fatal("changed source inherited authority")
			}
			if e = os.WriteFile(first, raw, 0600); e != nil {
				t.Fatal(e)
			}
			c.listed.Imports = append(slices.Clone(seal.imports), "net/rpc")
			if reviewedDebianBaselinePackage(c, module, relative) {
				t.Fatal("extra import inherited authority")
			}
			c.listed.Imports = slices.Clone(seal.imports)
			c.listed.GoFiles = append(slices.Clone(names), "extra.go")
			if e = os.WriteFile(filepath.Join(dir, "extra.go"), []byte("package debianbaseline\n"), 0600); e != nil {
				t.Fatal(e)
			}
			if reviewedDebianBaselinePackage(c, module, relative) {
				t.Fatal("extra file inherited authority")
			}
			c.listed.GoFiles = slices.Clone(names)
			c.listed.GoFiles[0] = "renamed.go"
			if e = os.WriteFile(filepath.Join(dir, "renamed.go"), raw, 0600); e != nil {
				t.Fatal(e)
			}
			if reviewedDebianBaselinePackage(c, module, relative) {
				t.Fatal("renamed file inherited authority")
			}
			c.listed.GoFiles = slices.Clone(names)
			c.listed.ImportPath = module + "/internal/sibling"
			if reviewedDebianBaselinePackage(c, module, relative) {
				t.Fatal("sibling package inherited authority")
			}
		})
	}
}

// Historical #369 digests describe the old source, never today's current files.
func TestFail2banStartupHistoricalSealsPreserved(t *testing.T) {
	if len(fail2banStartupSourceSeals) != 2 {
		t.Fatal("startup history widened")
	}
	for key, seal := range fail2banStartupSourceSeals {
		want := "0e6eff7ac20c1fbd4f5e59a7144dd0c83e87769b9d64388ca888770cea9477fd"
		if strings.Contains(key, "volume_linux.go") {
			want = "2f1c32ccc43f6343592b3b0f811645fa0204cb74554fc09c26b41ce9e8d79c23"
		}
		if seal.digest != want {
			t.Fatal("historical startup seal changed")
		}
		current, ok := fail2banJournalSourceSeals[key]
		if !ok || !slices.Equal(current.imports, seal.imports) || current.digest == seal.digest {
			t.Fatal("current journal variant lost exact startup import/file binding")
		}
	}
}
