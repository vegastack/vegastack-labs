package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxRoleBoundaryExceptionsRequireExactReviewedFiles(t *testing.T) {
	for _, relative := range []string{
		"internal/store/host_role_reservation.go",
		"internal/linuxrole/boot_linux.go",
		"internal/linuxrole/control_handoff_linux.go",
		"internal/linuxrole/isolation_linux.go",
		"internal/linuxrole/runtime_linux.go",
	} {
		content, err := os.ReadFile(filepath.Join("..", "..", relative))
		if err != nil {
			t.Fatal(err)
		}
		for _, variant := range []string{"reviewed", "changed", "sibling"} {
			t.Run(relative+"/"+variant, func(t *testing.T) {
				target, source := relative, append([]byte(nil), content...)
				if variant == "changed" {
					source = append(source, []byte("\n// changed source must lose authority\n")...)
				}
				if variant == "sibling" {
					target = filepath.ToSlash(filepath.Join(filepath.Dir(relative), "unreviewed_linux.go"))
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
				denied := got.XSysOutsideScope
				if relative == "internal/store/host_role_reservation.go" {
					denied = got.ContextSetterOutside
				}
				if denied != (variant != "reviewed") {
					t.Fatalf("boundary denied=%v variant=%s", denied, variant)
				}
			})
		}
	}
}
