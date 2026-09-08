//go:build !linux

package localapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func TestUnsupportedListenDoesNotMutateFilesystem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	resolver, err := identity.NewLocalPrincipalResolver([]identity.Binding{{UID: 1, PrincipalID: "principal.test"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Listen(context.Background(), ListenConfig{Profile: serverconfig.Profile{SocketPath: path}, Resolver: resolver})
	if err == nil || !strings.Contains(err.Error(), "UNSUPPORTED_PLATFORM") || strings.Contains(err.Error(), path) {
		t.Fatalf("Listen() error = %v", err)
	}
	if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		t.Fatalf("socket path was created: %v", statErr)
	}
}
