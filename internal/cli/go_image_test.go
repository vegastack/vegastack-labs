package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoImageCommandReachableAndSafe(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr, BuildInfo{}, func() (string, error) { return "request-test-1", nil })
	args := []string{"release", "build-go-image", "--binary", "nonexistent-private-path", "--source-uri", "https://example.org/app", "--source-revision", strings.Repeat("a", 40), "--builder-id", "https://example.org/builder", "--invocation-id", "https://example.org/run/1", "--directory", "nonexistent-output", "--output", "json"}
	code := app.Run(context.Background(), args)
	if code == 0 {
		t.Fatal("missing binary accepted")
	}
	if strings.Contains(stdout.String()+stderr.String(), "nonexistent-private-path") {
		t.Fatal("path leaked")
	}
	if !strings.Contains(stdout.String(), "release build-go-image") {
		t.Fatal("command unreachable", stdout.String(), stderr.String())
	}
}

func TestGoImageCLIActualCompileAndOutput(t *testing.T) {
	source := t.TempDir()
	for name, body := range map[string]string{"go.mod": "module example.org/real-cli-app\n\ngo 1.27\n", "main.go": "package main\nfunc main(){}\n"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(name string, args ...string) string {
		t.Helper()
		c := exec.Command(name, args...)
		c.Dir = source
		c.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
		out, e := c.CombinedOutput()
		if e != nil {
			t.Fatalf("%s: %v %s", name, e, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("git", "init", "-q")
	run("git", "add", ".")
	run("git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.org", "commit", "-qm", "source")
	revision := run("git", "rev-parse", "HEAD")
	binary := filepath.Join(t.TempDir(), "application")
	run("go", "build", "-buildvcs=true", "-o", binary, ".")
	output := filepath.Join(t.TempDir(), "oci")
	args := []string{"release", "build-go-image", "--binary", binary, "--source-uri", "https://example.org/real-cli-app", "--source-revision", revision, "--builder-id", "https://example.org/packager", "--invocation-id", "https://example.org/runs/one", "--directory", output, "--output", "json"}
	code, stdout, stderr := runTestApp(t, context.Background(), args, nil)
	if code != 0 || stderr != "" || !strings.Contains(stdout, `"signatureStatus":"unsigned"`) || !strings.Contains(stdout, `"provenanceScope":"binary-packaging-only"`) {
		t.Fatal(code, stdout, stderr)
	}
	for _, name := range []string{"oci-layout", "index.json", "provenance.statement.json", "sbom.statement.json", "expectations.json"} {
		if _, e := os.Stat(filepath.Join(output, name)); e != nil {
			t.Fatal(e)
		}
	}
	code, _, _ = runTestApp(t, context.Background(), args, nil)
	if code == 0 {
		t.Fatal("output overwritten")
	}
	// An actual recompile after changing source must be denied as dirty.
	if e := os.WriteFile(filepath.Join(source, "main.go"), []byte("package main\nfunc main(){println(1)}\n"), 0600); e != nil {
		t.Fatal(e)
	}
	run("go", "build", "-buildvcs=true", "-o", binary, ".")
	args[len(args)-3] = filepath.Join(t.TempDir(), "dirty-output")
	code, stdout, stderr = runTestApp(t, context.Background(), args, nil)
	if code == 0 {
		t.Fatal("dirty binary accepted", stdout, stderr)
	}
}
