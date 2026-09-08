package localapi

import (
	"net"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/identity"
)

type testConn struct{ net.Conn }

func TestAuthenticatedConnectionCarriesOnlyResolvedPrincipal(t *testing.T) {
	left, right := net.Pipe()
	t.Cleanup(func() { _ = right.Close() })
	principal := identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod}
	connection := newAuthenticatedConn(left, principal, nil)
	if got := connection.Principal(); got != principal {
		t.Fatalf("Principal() = %#v", got)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
}
