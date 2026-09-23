//go:build linux

package backup

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
	socket := shortRESTSocketPath(t)
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

// Unix socket names have a much smaller path limit than ordinary files. Keep
// the socket beneath the protected test TMPDIR without the test-name suffix.
func shortRESTSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "vsk-rest-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return filepath.Join(directory, "rest.sock")
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
	socket := shortRESTSocketPath(t)
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

func TestVerifierRESTBoundaryReadsButOnlyMutatesOwnLocks(t *testing.T) {
	writer, client, done := newRESTFixture(t)
	defer done()
	name := strings.Repeat("a", 64)
	if code := restDo(t, client, http.MethodPost, "/repo-a/data/"+name, []byte("retained")); code != http.StatusOK {
		t.Fatalf("seed retained object = %d", code)
	}
	readLease := ReadLease{LeaseID: "read-a", PointID: "point-a", RepositoryID: "repo-a", RecoveryEpoch: writer.lease.RecoveryEpoch, MaximumExpiresAt: time.Now().Add(time.Hour)}
	verifier, err := NewVerifierRESTServer(writer.root, uint32(os.Geteuid()), readLease, allowingReadLeaseVerifier{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if code := restRequestCode(t, verifier, method, "/repo-a/data/"+name, []byte("replacement")); code != http.StatusForbidden {
			t.Fatalf("%s retained = %d", method, code)
		}
	}
	if code := restRequestCode(t, verifier, http.MethodPost, "/repo-a/?create=true", nil); code != http.StatusForbidden {
		t.Fatalf("repository create = %d", code)
	}
	if code := restRequestCode(t, verifier, http.MethodGet, "/repo-a/data/"+name, nil); code != http.StatusOK {
		t.Fatalf("retained read = %d", code)
	}
	lock := strings.Repeat("b", 64)
	if code := restRequestCode(t, verifier, http.MethodPost, "/repo-a/locks/"+lock, []byte("lock")); code != http.StatusOK {
		t.Fatalf("own lock create = %d", code)
	}
	if code := restRequestCode(t, verifier, http.MethodDelete, "/repo-a/locks/"+lock, nil); code != http.StatusOK {
		t.Fatalf("own lock delete = %d", code)
	}
	if code := restRequestCode(t, verifier, http.MethodDelete, "/repo-a/locks/"+strings.Repeat("c", 64), nil); code != http.StatusForbidden {
		t.Fatalf("foreign lock delete = %d", code)
	}
}

type allowingReadLeaseVerifier struct{}

func (allowingReadLeaseVerifier) VerifyReadLease(ReadLease, time.Time) error { return nil }

func restRequestCode(t *testing.T, server *RESTServer, method, path string, body []byte) int {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response.Code
}
