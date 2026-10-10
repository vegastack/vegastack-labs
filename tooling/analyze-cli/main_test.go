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

func TestPhase228ReceiveSubprocessRejectsDriftAndSecondExecFile(t *testing.T) {
	const server = "github.com/vegastack/vegastack-labs/internal/server"
	dir := t.TempDir()
	name := "recovery_receive_linux.go"
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "server", name))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
		t.Fatal(err)
	}
	c := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{ImportPath: server, Dir: dir, GoFiles: []string{name}}}}
	if !reviewedPhase228ReceiveProcess(c, server) {
		t.Fatal("reviewed same-executable receiver refused")
	}
	if err = os.WriteFile(filepath.Join(dir, name), append(append([]byte(nil), raw...), []byte("\n// unreviewed process change\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if reviewedPhase228ReceiveProcess(c, server) {
		t.Fatal("receiver source drift inherited process authority")
	}
	if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "extra.go"), []byte("package server\nimport \"os/exec\"\nvar added=exec.Command\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c.listed.GoFiles = append(c.listed.GoFiles, "extra.go")
	if reviewedPhase228ReceiveProcess(c, server) {
		t.Fatal("second subprocess file inherited receiver authority")
	}
}

func TestPhase228GrantPredicatesAllowanceIsOneExactRange(t *testing.T) {
	const module = "github.com/vegastack/vegastack-labs"
	dir := t.TempDir()
	name := "recovery_source_suspend.go"
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "store", name))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), name, raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	c := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{ImportPath: module + "/internal/store", Dir: dir, GoFiles: []string{name}}, files: []*ast.File{file}}}
	var literal *ast.CompositeLit
	ast.Inspect(file, func(node ast.Node) bool {
		if statement, ok := node.(*ast.RangeStmt); ok {
			if value, ok := statement.X.(*ast.CompositeLit); ok && len(value.Elts) == 3 {
				literal = value
			}
		}
		return true
	})
	if literal == nil || !reviewedRecoveryGrantPredicates(c, file, literal, module+"/internal/generated") {
		t.Fatal("exact grant-data range refused")
	}
	if reviewedRecoveryGrantPredicates(c, file, &ast.CompositeLit{Elts: literal.Elts}, module+"/internal/generated") {
		t.Fatal("another registry inherited grant-data allowance")
	}
	if err = os.WriteFile(filepath.Join(dir, name), append(raw, []byte("\n// changed grant predicate\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if reviewedRecoveryGrantPredicates(c, file, literal, module+"/internal/generated") {
		t.Fatal("changed predicates inherited allowance")
	}
}

func TestReviewedNativeCredentialPackageIsExact(t *testing.T) {
	// Current source is accepted through the separately sealed #223 wave.
	// Historical native credential seals remain untouched in the verifier.
	imports := []string{"bytes", "context", "crypto/sha256", "crypto/subtle", "encoding/hex", "encoding/json", "errors", "fmt", "github.com/godbus/dbus/v5", "example.test/internal/credentialref", "example.test/internal/failure", "example.test/internal/generated", "golang.org/x/sys/unix", "io", "os", "os/exec", "os/user", "path/filepath", "reflect", "regexp", "slices", "strconv", "strings", "syscall", "time"}
	files := []string{"authority_linux.go", "effective_policy_linux.go", "encrypt_linux.go", "inspect_linux.go", "lifecycle_verifier_linux.go", "loaded_observer.go", "loaded_observer_linux.go", "native_restart_linux.go", "observation_linux.go", "policy_check_linux.go", "probe_linux.go", "process_observer_linux.go", "resolver_linux.go", "systemd_linux.go", "verify_recovery_linux.go"}
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
