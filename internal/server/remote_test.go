package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/identity"
)

func TestRemoteListenRejectsMissingTLSMaterialWithoutLeakingPaths(t *testing.T) {
	canary := "/private/console-key-canary"
	_, err := RemoteListen(context.Background(), RemoteListenConfig{Address: "127.0.0.1:0", CertificatePath: canary + ".crt", PrivateKeyPath: canary + ".key"})
	if err == nil || strings.Contains(err.Error(), canary) {
		t.Fatalf("RemoteListen() error = %v", err)
	}
}

func TestRemoteListenAcceptsTLS13Only(t *testing.T) {
	certificatePath, keyPath := writeRemoteTestCertificate(t)
	listener, err := RemoteListen(context.Background(), RemoteListenConfig{Address: "127.0.0.1:0", CertificatePath: certificatePath, PrivateKeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			defer connection.Close()
			if tlsConnection, ok := connection.(*tls.Conn); !ok {
				acceptErr = net.ErrClosed
			} else {
				acceptErr = tlsConnection.Handshake()
			}
		}
		accepted <- acceptErr
	}()
	certificate, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatal("test certificate did not parse")
	}
	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	if client.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatalf("TLS version = %x", client.ConnectionState().Version)
	}
	_ = client.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestRemoteListenRejectsUnsafePrivateKeyFiles(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, string) string{
		"weak mode": func(t *testing.T, keyPath string) string {
			if err := os.Chmod(keyPath, 0o644); err != nil {
				t.Fatal(err)
			}
			return keyPath
		},
		"symlink": func(t *testing.T, keyPath string) string {
			link := filepath.Join(filepath.Dir(keyPath), "linked.key")
			if err := os.Symlink(keyPath, link); err != nil {
				t.Fatal(err)
			}
			return link
		},
		"non-regular": func(t *testing.T, keyPath string) string {
			directory := filepath.Join(filepath.Dir(keyPath), "key-directory")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			return directory
		},
	} {
		t.Run(name, func(t *testing.T) {
			certificatePath, keyPath := writeRemoteTestCertificate(t)
			keyPath = mutate(t, keyPath)
			if listener, err := RemoteListen(context.Background(), RemoteListenConfig{Address: "127.0.0.1:0", CertificatePath: certificatePath, PrivateKeyPath: keyPath}); err == nil {
				_ = listener.Close()
				t.Fatal("unsafe private key was accepted")
			}
		})
	}
}

func TestRemoteListenRejectsOversizedTLSMaterial(t *testing.T) {
	certificatePath, keyPath := writeRemoteTestCertificate(t)
	if err := os.WriteFile(certificatePath, bytes.Repeat([]byte("x"), maxTLSMaterialBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if listener, err := RemoteListen(context.Background(), RemoteListenConfig{Address: "127.0.0.1:0", CertificatePath: certificatePath, PrivateKeyPath: keyPath}); err == nil {
		_ = listener.Close()
		t.Fatal("oversized certificate was accepted")
	}
}

func TestRemoteExecutorAuthenticationUsesExactMachineIdentityWithoutBrowserSession(t *testing.T) {
	authenticator, adapter, sessions := newBrowserAuthFixture(t)
	sessions.principal = identity.Principal{ID: "principal.executor", Method: identity.CloudflareAccessMethod, Kind: identity.PrincipalAgent}
	downstreamCalls := atomic.Int32{}
	handler := authenticator.WrapExecutor(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		downstreamCalls.Add(1)
		principal, ok := identity.PrincipalFromContext(request.Context())
		if !ok || principal != sessions.principal {
			t.Fatalf("executor principal = %#v, %t", principal, ok)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "https://console.example/api/v1/executor-leases/claim", strings.NewReader(`{}`))
	request.Host = "console.example"
	request.Header.Set("Cf-Access-Jwt-Assertion", "verified-provider-assertion")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || downstreamCalls.Load() != 1 || adapter.calls.Load() != 1 || sessions.validates.Load() != 0 {
		t.Fatalf("status/calls = %d/%d/%d/%d", response.Code, downstreamCalls.Load(), adapter.calls.Load(), sessions.validates.Load())
	}
}

func TestRemoteExecutorAuthenticationRejectsBrowserAndForgedRequests(t *testing.T) {
	for _, mutate := range []func(*http.Request, *browserSessionStore){
		func(_ *http.Request, sessions *browserSessionStore) {
			sessions.principal.ID = "invalid principal"
		},
		func(request *http.Request, _ *browserSessionStore) {
			request.Header.Set("Origin", "https://console.example")
		},
		func(request *http.Request, sessions *browserSessionStore) {
			request.AddCookie(&http.Cookie{Name: BrowserSessionCookieName, Value: sessions.raw})
		},
		func(request *http.Request, _ *browserSessionStore) { request.Host = "internal.example" },
		func(request *http.Request, _ *browserSessionStore) {
			request.Header.Add("Cf-Access-Jwt-Assertion", "duplicate")
		},
	} {
		authenticator, _, sessions := newBrowserAuthFixture(t)
		sessions.principal = identity.Principal{ID: "principal.executor", Method: identity.CloudflareAccessMethod, Kind: identity.PrincipalAgent}
		calls := atomic.Int32{}
		handler := authenticator.WrapExecutor(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
		request := httptest.NewRequest(http.MethodPost, "https://console.example/api/v1/executor-leases/claim", strings.NewReader(`{"private":"canary"}`))
		request.Host = "console.example"
		request.Header.Set("Cf-Access-Jwt-Assertion", "verified-provider-assertion")
		mutate(request, sessions)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || calls.Load() != 0 || strings.Contains(response.Body.String(), "canary") {
			t.Fatalf("status/calls/body = %d/%d/%s", response.Code, calls.Load(), response.Body.String())
		}
	}
}

func writeRemoteTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"console.example"},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "console.crt")
	keyPath := filepath.Join(directory, "console.key")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certificatePath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	return certificatePath, keyPath
}
