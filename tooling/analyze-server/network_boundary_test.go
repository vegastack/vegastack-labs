package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNetworkBoundaryExceptionsRequireExactSource(t *testing.T) {
	for _, relative := range []string{
		"internal/store/network_endpoint_execution.go",
		"internal/store/mesh_repository.go",
		"internal/store/ingress_repository.go",
		"internal/networkconnect/private_key_unix.go",
	} {
		content, err := os.ReadFile(filepath.Join("..", "..", relative))
		if err != nil {
			t.Fatal(err)
		}
		for _, variant := range []string{"approved", "mutated", "sibling", "different-package"} {
			t.Run(relative+"/"+variant, func(t *testing.T) {
				target, source := relative, append([]byte(nil), content...)
				switch variant {
				case "mutated":
					source = append(source, []byte("\n// unapproved source mutation\n")...)
				case "sibling":
					target = filepath.ToSlash(filepath.Join(filepath.Dir(relative), "unapproved.go"))
				case "different-package":
					target = "internal/other/" + filepath.Base(relative)
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
				denied := got.ContextSetterOutside
				if relative == "internal/networkconnect/private_key_unix.go" {
					denied = got.XSysOutsideScope
				}
				if denied != (variant != "approved") {
					t.Fatalf("denied=%v variant=%s", denied, variant)
				}
			})
		}
	}
}
