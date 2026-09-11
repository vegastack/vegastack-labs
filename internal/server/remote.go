package server

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
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
	certificate, err := tls.LoadX509KeyPair(config.CertificatePath, config.PrivateKeyPath)
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
	return tls.NewListener(listener, tlsConfig), nil
}
