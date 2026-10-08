package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReviewedSetupGrantCopyOnlyExactOwnerAndSite(t *testing.T) {
	original, err := os.ReadFile(filepath.Join("..", "..", "internal", "server", "local_setup_run.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, pkg, filename, text string
		want                      bool
	}{
		{"approved", "server", "local_setup_run.go", string(original), true},
		{"portable-cli", "cli", "local_setup_run.go", string(original), false},
		{"other-file", "server", "bypass.go", string(original), false},
		{"widened-grant", "server", "local_setup_run.go", strings.Replace(string(original), "ResourceID: g.ResourceID", `ResourceID: "*"`, 1), false},
		{"extra-dispatch", "server", "local_setup_run.go", string(original) + "\nvar routes = map[string]func(){\"apply\": func(){}}\n", false},
		{"changed-owner", "server", "local_setup_run.go", strings.Replace(string(original), "func (review localSetupReview) initialSetup", "func (review localSetupReview) otherSetup", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.WriteFile(filepath.Join(directory, tc.filename), []byte(tc.text), 0600); err != nil {
				t.Fatal(err)
			}
			file, err := parser.ParseFile(token.NewFileSet(), tc.filename, tc.text, 0)
			if err != nil {
				t.Fatal(err)
			}
			candidate := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{ImportPath: "example.test/internal/" + tc.pkg, Dir: directory, GoFiles: []string{tc.filename}}, files: []*ast.File{file}}}
			accepted, inspected := 0, 0
			ast.Inspect(file, func(node ast.Node) bool {
				if statement, ok := node.(*ast.AssignStmt); ok {
					inspected++
					if reviewedSetupGrantCopy(candidate, file, statement, "example.test/internal/generated") {
						accepted++
					}
				}
				return true
			})
			if inspected == 0 {
				t.Fatal("fixture did not exercise assignments")
			}
			want := 0
			if tc.want {
				want = 1
			}
			if accepted != want {
				t.Fatalf("accepted %d assignments, want %d", accepted, want)
			}
			// A separately parsed lookalike site cannot borrow the reviewed source.
			lookalike, _ := parser.ParseFile(token.NewFileSet(), "extra.go", "package server; func extra(){ result.EffectiveGrants = append(result.EffectiveGrants, store.InitialEffectiveGrant{}) }", 0)
			ast.Inspect(lookalike, func(node ast.Node) bool {
				if statement, ok := node.(*ast.AssignStmt); ok && reviewedSetupGrantCopy(candidate, lookalike, statement, "example.test/internal/generated") {
					t.Fatal("extra source inherited setup allowance")
				}
				return true
			})
		})
	}
}

func TestReviewedSetupProfileRejectsChangedAndAddedSource(t *testing.T) {
	for _, platform := range []string{"linux", "unsupported"} {
		t.Run(platform, func(t *testing.T) {
			directory := t.TempDir()
			names := []string{"profile.go", "profile_" + platform + ".go", "restic.go"}
			for _, name := range names {
				raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "serverconfig", name))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			candidate := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{Dir: directory, GoFiles: names}}}
			if !reviewedControlPlatformSource(candidate, "serverconfig") {
				t.Fatal("reviewed frozen-profile decoder rejected")
			}
			filename := filepath.Join(directory, "profile.go")
			original, _ := os.ReadFile(filename)
			for _, addition := range []string{"\n// changed profile parsing\n", "\nfunc bypass(){ exec.Command(\"sh\") }\n", "\nfunc bypass(){ sql.Open(\"sqlite\",\"control.db\") }\n", "\nfunc bypass(){ provider.Apply() }\n"} {
				if err := os.WriteFile(filename, append(append([]byte(nil), original...), []byte(addition)...), 0600); err != nil {
					t.Fatal(err)
				}
				if reviewedControlPlatformSource(candidate, "serverconfig") {
					t.Fatal("changed profile inherited allowance")
				}
			}
			if err := os.WriteFile(filename, original, 0600); err != nil {
				t.Fatal(err)
			}
			candidate.listed.GoFiles = append(candidate.listed.GoFiles, "bypass.go")
			if reviewedControlPlatformSource(candidate, "serverconfig") {
				t.Fatal("added profile file inherited allowance")
			}
		})
	}
}
