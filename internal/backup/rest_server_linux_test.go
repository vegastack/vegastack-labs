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
