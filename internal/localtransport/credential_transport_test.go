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
