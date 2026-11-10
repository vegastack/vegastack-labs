package localtransport

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPaginationCannotWidenLocalTransport(t *testing.T) {
	for _, requestPath := range []string{
		"/api/v1/ci/enrollments?limit=1", "/api/v1/ci/enrollments?after=enrollment%3Aa&limit=100",
		"/api/v1/services?limit=1", "/api/v1/services?limit=50", "/api/v1/services?after=service%3Aa&limit=100",
	} {
		if !validRequest(Request{SocketPath: "/tmp/control.sock", Method: MethodGet, Path: requestPath, Timeout: time.Second, ResponseLimit: 4096}) {
			t.Fatalf("bounded list pagination rejected: %s", requestPath)
		}
	}
	for _, requestPath := range []string{
		"/api/v1/services?", "/api/v1/services?after=service-a",
		"/api/v1/services?limit=0", "/api/v1/services?limit=101", "/api/v1/services?limit=01",
		"/api/v1/services?limit=1&limit=2", "/api/v1/services?limit=1&scope=all",
		"/api/v1/services?after=..%2Fother&limit=1", "/api/v1/services?after=%252Fother&limit=1",
		"/api/v1/services?after=&limit=1", "/api/v1/services?limit=1#other",
		"/api/v1/services?limit=1&after=service-a", "/api/v1/services?after=service%3aa&limit=1",
		"/api/v1/services/service-a?limit=1", "/api/v1/services/?limit=1", "https://other.example/api/v1/services?limit=1",
		"/api/v1/ci/enrollments?", "/api/v1/ci/enrollments?after=enrollment-a",
		"/api/v1/ci/enrollments?limit=0", "/api/v1/ci/enrollments?limit=101", "/api/v1/ci/enrollments?limit=01",
		"/api/v1/ci/enrollments?limit=1&limit=2", "/api/v1/ci/enrollments?limit=1&scope=all",
		"/api/v1/ci/enrollments?after=..%2Fother&limit=1", "/api/v1/ci/enrollments?after=%252Fother&limit=1",
		"/api/v1/ci/enrollments?after=&limit=1", "/api/v1/ci/enrollments?limit=1#other",
		"/api/v1/ci/enrollments?limit=1&after=enrollment-a", "/api/v1/ci/enrollments?after=enrollment%3aa&limit=1",
		"/api/v1/ci/enrollments/enrollment-a?limit=1", "/api/v1/health?limit=1", "https://other.example/api/v1/ci/enrollments?limit=1",
	} {
		if validRequest(Request{SocketPath: "/tmp/control.sock", Method: MethodGet, Path: requestPath, Timeout: time.Second, ResponseLimit: 4096}) {
			t.Fatalf("widened query accepted: %s", requestPath)
		}
	}
	for _, requestPath := range []string{"/api/v1/ci/enrollments?limit=1", "/api/v1/services?limit=1"} {
		if validRequest(Request{SocketPath: "/tmp/control.sock", Method: MethodPost, Path: requestPath, Body: []byte("{}"), Timeout: time.Second, ResponseLimit: 4096}) {
			t.Fatal("query accepted for a mutation")
		}
	}
}

func TestCredentialBinaryRequestIsExactLocalOnlyAndBounded(t *testing.T) {
	metadata := []byte(`{"schema":"vegastack-labs.dev/credential-import-request"}`)
	request := Request{SocketPath: "/tmp/control.sock", Method: MethodPost, Path: "/api/v1/credential-references/ref-a/import-stream", Body: []byte("synthetic-private-canary"), Timeout: time.Second, ResponseLimit: 4096, BinaryCredential: true, CredentialMetadata: metadata}
	if !validRequest(request) {
		t.Fatal("exact local credential binary request rejected")
	}
	for _, alter := range []Request{
		func() Request { value := request; value.Path = "/api/v1/plans/plan-a/execute"; return value }(),
		func() Request { value := request; value.Method = MethodGet; return value }(),
		func() Request { value := request; value.Body = []byte(strings.Repeat("x", 4097)); return value }(),
		func() Request {
			value := request
			value.CredentialMetadata = []byte(strings.Repeat("x", 4097))
			return value
		}(),
	} {
		if validRequest(alter) {
			t.Fatalf("widened binary credential request accepted: %s %s", alter.Method, alter.Path)
		}
	}
	plain := request
	plain.BinaryCredential, plain.CredentialMetadata = false, nil
	if !validRequest(plain) {
		t.Fatal("historical ordinary JSON request rejected")
	}
	plain.CredentialMetadata = metadata
	if validRequest(plain) {
		t.Fatal("metadata accepted on generic JSON request")
	}
}

func TestCredentialBinaryRoundTripEmitsOnlyBoundedLocalHeaders(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "vsk124-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	metadata := []byte(`{"schema":"vegastack-labs.dev/credential-import-request"}`)
	seen := make(chan error, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil || r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("X-Vsk-Credential-Request") != base64.RawURLEncoding.EncodeToString(metadata) || string(body) != "synthetic-private-canary" {
			seen <- ErrInvalid
		} else {
			seen <- nil
		}
		_, _ = w.Write([]byte("{}\n"))
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	_, err = RoundTrip(context.Background(), Request{SocketPath: socket, Method: MethodPost, Path: "/api/v1/credential-references/ref-a/import-stream", Body: []byte("synthetic-private-canary"), BinaryCredential: true, CredentialMetadata: metadata, Timeout: time.Second, ResponseLimit: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-seen; err != nil {
		t.Fatal(err)
	}
}
