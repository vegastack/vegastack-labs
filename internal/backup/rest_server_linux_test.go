//go:build linux

package backup

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type allowingLeaseVerifier struct{ err error }

func (verifier allowingLeaseVerifier) VerifyWriterLease(WriterLease, time.Time) error {
	return verifier.err
}

func newRESTFixture(t *testing.T) (*RESTServer, *http.Client, func()) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "repo-a")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	lease := WriterLease{
		LeaseID: "lease-a", PolicyID: "policy-a", PlanID: "plan-a", PlanDigest: "sha256:" + strings.Repeat("a", 64),
		RunID: "run-a", StepID: "step-a", RepositoryID: "repo-a", RepositoryClass: "standard", TargetID: "target-a",
		RecoveryEpoch: 0, MaximumExpiresAt: time.Now().Add(time.Hour),
	}
	server, err := NewRESTServer(root, uint32(os.Geteuid()), lease, allowingLeaseVerifier{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "rest.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = server.Serve(ctx, listener) }()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	return server, client, func() { cancel(); _ = listener.Close() }
}

func restDo(t *testing.T, client *http.Client, method, path string, body []byte) int {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequest(method, "http://unix"+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return response.StatusCode
}

func TestRESTBoundaryCreatesButCannotRewriteOrDeleteRetainedObject(t *testing.T) {
	_, client, done := newRESTFixture(t)
	defer done()
	name := strings.Repeat("b", 64)
	if code := restDo(t, client, http.MethodPost, "/repo-a/data/"+name, []byte("first")); code != http.StatusOK {
		t.Fatalf("create = %d", code)
	}
	if code := restDo(t, client, http.MethodPost, "/repo-a/data/"+name, []byte("second")); code != http.StatusConflict {
		t.Fatalf("rewrite = %d, want 409", code)
	}
	if code := restDo(t, client, http.MethodDelete, "/repo-a/data/"+name, nil); code != http.StatusForbidden {
		t.Fatalf("delete retained = %d, want 403", code)
	}
	if code := restDo(t, client, http.MethodGet, "/repo-a/data/"+name, nil); code != http.StatusOK {
		t.Fatalf("get = %d", code)
	}
}

func TestRESTBoundaryImplementsResticV2RangeStatAndList(t *testing.T) {
	_, client, done := newRESTFixture(t)
	defer done()
	if code := restDo(t, client, http.MethodPost, "/repo-a/?create=true", nil); code != http.StatusOK {
		t.Fatalf("repository create = %d", code)
	}
	if code := restDo(t, client, http.MethodPost, "/repo-a/", nil); code != http.StatusMethodNotAllowed {
		t.Fatalf("repository create without token = %d", code)
	}
	name := strings.Repeat("a", 64)
	if code := restDo(t, client, http.MethodPost, "/repo-a/data/"+name, []byte("abcdef")); code != http.StatusOK {
		t.Fatalf("object create = %d", code)
	}
	request, err := http.NewRequest(http.MethodGet, "http://unix/repo-a/data/"+name, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Range", "bytes=2-4")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusPartialContent || string(body) != "cde" || response.ContentLength != 3 {
		t.Fatalf("range status=%d length=%d body=%q err=%v", response.StatusCode, response.ContentLength, body, err)
	}
	request, _ = http.NewRequest(http.MethodHead, "http://unix/repo-a/data/"+name, nil)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength != 6 {
		t.Fatalf("stat status=%d length=%d", response.StatusCode, response.ContentLength)
	}
	request, _ = http.NewRequest(http.MethodGet, "http://unix/repo-a/data/", nil)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/vnd.x.restic.rest.v2" || !bytes.Contains(body, []byte(name)) || !bytes.Contains(body, []byte(`"size":6`)) {
		t.Fatalf("list status=%d body=%q err=%v", response.StatusCode, body, err)
	}
}

func TestRESTBoundaryManagesOwnLockLifecycle(t *testing.T) {
	_, client, done := newRESTFixture(t)
	defer done()
	name := strings.Repeat("c", 64)
	if code := restDo(t, client, http.MethodPost, "/repo-a/locks/"+name, []byte("lock")); code != http.StatusOK {
		t.Fatalf("lock create = %d", code)
	}
	if code := restDo(t, client, http.MethodDelete, "/repo-a/locks/"+name, nil); code != http.StatusOK {
		t.Fatalf("own lock delete = %d", code)
	}
}

func TestRESTBoundaryRejectsUnsafePathsAndExpiredLease(t *testing.T) {
	_, client, done := newRESTFixture(t)
	defer done()
	for _, path := range []string{"/repo-a/../config", "/repo-a/data/short", "/repo-b/data/" + strings.Repeat("d", 64)} {
		if code := restDo(t, client, http.MethodPost, path, []byte("x")); code != http.StatusForbidden && code != http.StatusNotFound {
			t.Fatalf("unsafe path %q = %d", path, code)
		}
	}
}

func TestRESTBoundaryRejectsWhenLeaseVerifierDenies(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo-a")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	lease := WriterLease{LeaseID: "lease-a", RepositoryID: "repo-a", RepositoryClass: "standard", MaximumExpiresAt: time.Now().Add(time.Hour)}
	server, err := NewRESTServer(root, uint32(os.Geteuid()), lease, allowingLeaseVerifier{err: io.EOF}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "rest.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx, listener) }()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	if code := restDo(t, client, http.MethodPost, "/repo-a/data/"+strings.Repeat("e", 64), []byte("x")); code != http.StatusForbidden {
		t.Fatalf("denied lease = %d, want 403", code)
	}
}

func TestRepositoryFormatReadsGuardedRetainedConfig(t *testing.T) {
	server, _, done := newRESTFixture(t)
	defer done()
	for name, body := range map[string]string{
		"v1":              `{"version":1,"id":"old"}`,
		"missing version": `{"id":"missing"}`,
		"missing id":      `{"version":2}`,
		"malformed":       `{"version":2`,
		"trailing object": `{"version":2}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(server.root, "config"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := server.RepositoryFormat(); err == nil {
				t.Fatal("invalid retained config accepted")
			}
		})
	}
	if err := os.WriteFile(filepath.Join(server.root, "config"), []byte(`{"version":2,"id":"`+strings.Repeat("a", 64)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if format, err := server.RepositoryFormat(); err != nil || format != 2 {
		t.Fatalf("valid config = %d, %v", format, err)
	}
	if err := os.Remove(filepath.Join(server.root, "config")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(server.root, "outside"), filepath.Join(server.root, "config")); err != nil {
		t.Fatal(err)
	}
	if _, err := server.RepositoryFormat(); err == nil {
		t.Fatal("symlinked config accepted")
	}
}
