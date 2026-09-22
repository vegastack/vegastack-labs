package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReviewedNativeCredentialPackageIsExact(t *testing.T) {
	imports := []string{
		"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "fmt",
		"io", "os", "os/exec", "path/filepath", "reflect", "regexp", "slices", "strconv", "strings", "syscall", "time", "golang.org/x/sys/unix",
		"example.test/internal/credentialref", "example.test/internal/failure", "example.test/internal/generated",
	}
	files := []string{"authority_linux.go", "effective_policy_linux.go", "encrypt_linux.go", "inspect_linux.go", "policy_check_linux.go", "probe_linux.go", "resolver_linux.go"}

	sourceRoot := filepath.Join("..", "..", "internal", "adapter", "nativecredential")
	canonical := make(map[string][]byte, len(files))
	for _, name := range files {
		content, err := os.ReadFile(filepath.Join(sourceRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		canonical[name] = content
	}

	check := func(t *testing.T, replacements map[string][2]string, listedImports []string) bool {
		t.Helper()
		directory := t.TempDir()
		for _, name := range files {
			content := string(canonical[name])
			if replacement, ok := replacements[name]; ok {
				content = strings.Replace(content, replacement[0], replacement[1], 1)
				if content == string(canonical[name]) {
					t.Fatalf("mutation for %s did not change the source", name)
				}
			}
			if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return reviewedNativeCredentialPackage(checkedSourcePackage{listed: listedPackage{
			ImportPath: "example.test/internal/adapter/nativecredential",
			Dir:        directory, GoFiles: files, Imports: listedImports,
		}}, "example.test/internal/adapter/nativecredential", "example.test")
	}

	if !check(t, nil, imports) {
		t.Fatal("the exact reviewed native-credential package was rejected")
	}
	for _, mutation := range []struct {
		name string
		from string
		to   string
	}{
		{"command path", `const credsCommandPath = "/usr/bin/systemd-creds"`, `const credsCommandPath = "/usr/bin/sh"`},
		{"dispatch target", `exec.CommandContext(ctx, credsCommandPath, args...)`, `exec.CommandContext(ctx, "/bin/sh", args...)`},
		{"encrypt arguments", `"encrypt", "--with-key=host"`, `"encrypt", "--with-key=auto"`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			if check(t, map[string][2]string{"encrypt_linux.go": {mutation.from, mutation.to}}, imports) {
				t.Fatal("mutated native-credential shell dispatch was accepted")
			}
		})
	}
	if check(t, nil, append(append([]string(nil), imports...), "unsafe.example/helper")) {
		t.Fatal("native-credential package with a wider import surface was accepted")
	}
}
