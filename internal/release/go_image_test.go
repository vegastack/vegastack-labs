package release

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func compileImageBinary(t *testing.T) ([]byte, string) {
	t.Helper()
	root := t.TempDir()
	for p, s := range map[string]string{"go.mod": "module example.org/application\n\ngo 1.27\n", "main.go": "package main\nimport \"fmt\"\nfunc main(){fmt.Println(\"actual build\")}\n"} {
		if e := os.WriteFile(filepath.Join(root, p), []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
	}
	run := func(name string, args ...string) string {
		t.Helper()
		c := exec.Command(name, args...)
		c.Dir = root
		c.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
		b, e := c.CombinedOutput()
		if e != nil {
			t.Fatalf("%s %v: %v %s", name, args, e, b)
		}
		return strings.TrimSpace(string(b))
	}
	run("git", "init", "-q")
	run("git", "add", ".")
	run("git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.org", "commit", "-qm", "actual source")
	rev := run("git", "rev-parse", "HEAD")
	output := filepath.Join(t.TempDir(), "app")
	run("go", "build", "-buildvcs=true", "-o", output, ".")
	b, e := os.ReadFile(output)
	if e != nil {
		t.Fatal(e)
	}
	return b, rev
}
func TestBuildRealGoImage(t *testing.T) {
	binary, rev := compileImageBinary(t)
	q := GoImageRequest{Binary: binary, SourceURI: "https://example.org/application", SourceRevision: rev, BuilderID: "https://example.org/packager", InvocationID: "https://example.org/runs/1"}
	got, e := BuildGoImage(context.Background(), q)
	if e != nil {
		t.Fatal(e)
	}
	if hashOCI(got.Manifest) != got.Expected.ImageDigest {
		t.Fatal("image digest")
	}
	tr := tar.NewReader(bytes.NewReader(got.Layer))
	h, e := tr.Next()
	if e != nil || h.Name != "app" || h.Mode != 0555 {
		t.Fatal(h, e)
	}
	actual, e := io.ReadAll(tr)
	if e != nil || !bytes.Equal(actual, binary) {
		t.Fatal("binary not in image")
	}
	if _, e = tr.Next(); e != io.EOF {
		t.Fatal("extra image file", e)
	}
	p, e := statementPredicate(context.Background(), got.ProvenanceStatement, "https://slsa.dev/provenance/v1", got.Expected.ImageDigest)
	if e != nil {
		t.Fatal(e)
	}
	params, e := jsonObject(context.Background(), got.Expected.ExternalParameters)
	if e != nil {
		t.Fatal(e)
	}
	if e = checkProvenance(context.Background(), p, got.Expected, params); e != nil {
		t.Fatal(e)
	}
	s, e := statementPredicate(context.Background(), got.SBOMStatement, "https://spdx.dev/Document/v2.3", got.Expected.ImageDigest)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = checkSPDX(s, got.Expected.ImageDigest); e != nil {
		t.Fatal(e)
	}
	output := filepath.Join(t.TempDir(), "image")
	if e = WriteGoImage(context.Background(), output, got); e != nil {
		t.Fatal(e)
	}
	if e = WriteGoImage(context.Background(), output, got); e == nil {
		t.Fatal("overwrote output")
	}
	var layout map[string]any
	b, e := os.ReadFile(filepath.Join(output, "oci-layout"))
	if e != nil || json.Unmarshal(b, &layout) != nil || layout["imageLayoutVersion"] != "1.0.0" {
		t.Fatal("invalid layout", e)
	}
	for _, mutate := range []func(*GoImageRequest){func(q *GoImageRequest) { q.SourceRevision = strings.Repeat("a", 40) }, func(q *GoImageRequest) { q.Binary = []byte("not binary") }, func(q *GoImageRequest) { q.SourceURI = "relative" }, func(q *GoImageRequest) { q.BuilderID = "bad" }} {
		bad := q
		mutate(&bad)
		if _, e := BuildGoImage(context.Background(), bad); e == nil {
			t.Fatal("bad request accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := BuildGoImage(ctx, q); e == nil {
		t.Fatal("cancel ignored")
	}
}

func TestGoImageRejectsUnsignedPublicationEvidence(t *testing.T) {
	binary, revision := compileImageBinary(t)
	out, e := BuildGoImage(context.Background(), GoImageRequest{Binary: binary, SourceURI: "https://example.org/app", SourceRevision: revision, BuilderID: "https://example.org/builder", InvocationID: "https://example.org/run/1"})
	if e != nil {
		t.Fatal(e)
	}
	policy, e := os.ReadFile("testdata/policy-valid.json")
	if e != nil {
		t.Fatal(e)
	}
	_, e = VerifyBuildEvidenceBytes(context.Background(), BuildEvidenceRequest{Manifest: out.Manifest, Expected: out.Expected, Policy: policy, ProvenanceBundle: out.ProvenanceStatement, SBOMBundle: out.SBOMStatement})
	if e == nil {
		t.Fatal("unsigned payloads passed authenticated verification")
	}
}
