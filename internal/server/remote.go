package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

const (
	maxTLSMaterialBytes   = 1024 * 1024
	remoteConnectionLimit = 64
)

type RemoteListenConfig struct {
	Address         string
	CertificatePath string
	PrivateKeyPath  string
}

type RemoteListenerFactory func(context.Context, RemoteListenConfig) (net.Listener, error)

func RemoteListen(ctx context.Context, config RemoteListenConfig) (net.Listener, error) {
	if config.Address == "" || config.CertificatePath == "" || config.PrivateKeyPath == "" {
		return nil, failure.New(generated.ErrorCodeInputInvalid, "remote-listener", false)
	}
	certificate, err := loadProtectedTLSKeyPair(config.CertificatePath, config.PrivateKeyPath)
	if err != nil {
		return nil, failure.New(generated.ErrorCodeIntegrityFailure, "remote-tls-identity", false)
	}
	listener, err := (&net.ListenConfig{KeepAlive: 30 * time.Second}).Listen(ctx, "tcp", config.Address)
	if err != nil {
		return nil, failure.New(generated.ErrorCodeExecutionFailed, "remote-listener", false)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	}
	listener = newLimitedRemoteListener(listener, remoteConnectionLimit)
	return tls.NewListener(listener, tlsConfig), nil
}

// WrapExecutor admits machine calls only after the existing remote identity
// adapter verifies the assertion and its declared binding resolves to an
// authenticated principal. The lifecycle service separately reauthorizes that
// principal as the exact plan-declared executor. This wrapper accepts neither
// a browser Origin nor a browser session cookie, so browser sessions cannot
// become executor credentials and executor calls do not gain the wider browser
// API surface.
func (authenticator *BrowserAuthenticator) WrapExecutor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if next == nil || len(request.Header.Values("Origin")) != 0 || len(request.Header.Values("Cookie")) != 0 {
			authenticator.writeFailure(writer, generated.ErrorCodeAuthenticationRequired)
			return
		}
		ctx, verified, bindingDigest, ok := authenticator.verifyExternalRequest(request)
		if !ok {
			authenticator.writeFailure(writer, generated.ErrorCodeAuthenticationRequired)
			return
		}
		principal, err := authenticator.config.Sessions.ResolveRemoteIdentity(ctx, bindingDigest)
		if err != nil || principal.Method != verified.Method || !identity.ValidPrincipal(principal) {
			authenticator.writeFailure(writer, generated.ErrorCodeAuthenticationRequired)
			return
		}
		ctx = identity.WithVerifiedPrincipal(ctx, principal)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

type limitedRemoteListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}

func newLimitedRemoteListener(listener net.Listener, limit int) net.Listener {
	return &limitedRemoteListener{Listener: listener, slots: make(chan struct{}, limit), done: make(chan struct{})}
}

func (listener *limitedRemoteListener) Accept() (net.Conn, error) {
	select {
	case listener.slots <- struct{}{}:
	case <-listener.done:
		return nil, net.ErrClosed
	}
	connection, err := listener.Listener.Accept()
	if err != nil {
		<-listener.slots
		return nil, err
	}
	return &limitedRemoteConnection{Conn: connection, release: func() { <-listener.slots }}, nil
}

func (listener *limitedRemoteListener) Close() error {
	listener.once.Do(func() { close(listener.done) })
	return listener.Listener.Close()
}

type limitedRemoteConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (connection *limitedRemoteConnection) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(connection.release)
	return err
}
