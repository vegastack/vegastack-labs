// Package localapi owns the authenticated local API transport.
package localapi

import (
	"context"
	"net"
	"sync"

	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

type ListenConfig struct {
	Profile  serverconfig.Profile
	Resolver identity.LocalPrincipalResolver
}

type AuthenticatedConn interface {
	net.Conn
	Principal() identity.Principal
}

type Listener interface {
	net.Listener
	CheckPath() error
	Cleanup() error
}

type ListenerFactory func(context.Context, ListenConfig) (Listener, error)

type authenticatedConn struct {
	net.Conn
	principal identity.Principal
	onClose   func()
	once      sync.Once
}

func newAuthenticatedConn(connection net.Conn, principal identity.Principal, onClose func()) AuthenticatedConn {
	return &authenticatedConn{Conn: connection, principal: principal, onClose: onClose}
}

func (connection *authenticatedConn) Principal() identity.Principal {
	return connection.principal
}

func (connection *authenticatedConn) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(func() {
		if connection.onClose != nil {
			connection.onClose()
		}
	})
	return err
}
