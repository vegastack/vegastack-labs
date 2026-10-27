package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCINativeUnixScopeRequiresExactFiles(t *testing.T) {
	for _, relative := range []string{"internal/runnerbootstrap/config_linux.go", "internal/cijobguard/cgroup_linux.go"} {
		content, err := os.ReadFile(filepath.Join("..", "..", relative))
		if err != nil {
			t.Fatal(err)
		}
		for _, variant := range []string{"accepted", "changed", "sibling"} {
			t.Run(relative+"/"+variant, func(t *testing.T) {
				target, source := relative, append([]byte(nil), content...)
				if variant == "changed" {
					source = append(source, []byte("\n// altered native scope\n")...)
				}
				if variant == "sibling" {
					target = filepath.ToSlash(filepath.Join(filepath.Dir(relative), "extra_linux.go"))
				}
				root := t.TempDir()
				filename := filepath.Join(root, target)
				if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filename, source, 0600); err != nil {
					t.Fatal(err)
				}
				got, err := analyze(root)
				if err != nil {
					t.Fatal(err)
				}
				if got.XSysOutsideScope != (variant != "accepted") {
					t.Fatalf("denied=%v variant=%s", got.XSysOutsideScope, variant)
				}
			})
		}
	}
}
