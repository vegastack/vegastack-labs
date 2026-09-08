//go:build linux

package localapi

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func linuxTestConfig(t *testing.T, socketPath string) ListenConfig {
	t.Helper()
	uid := uint32(os.Geteuid())
	resolver, err := identity.NewLocalPrincipalResolver([]identity.Binding{{UID: uid, PrincipalID: "principal.test"}})
	if err != nil {
		t.Fatal(err)
	}
	return ListenConfig{Profile: serverconfig.Profile{
		SocketPath: socketPath, SocketOwnerUID: uid, SocketMode: 0o600, ShutdownGrace: 5 * time.Second,
		PrincipalBindings: []identity.Binding{{UID: uid, PrincipalID: "principal.test"}},
	}, Resolver: resolver}
}

func TestListenDoesNotRemoveNonSocketCollision(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(directory, "control.sock")
	if err := os.WriteFile(socketPath, []byte("operator-data\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(context.Background(), linuxTestConfig(t, socketPath)); err == nil {
		t.Fatal("Listen() accepted a regular-file collision")
	}
	content, err := os.ReadFile(socketPath)
	if err != nil || string(content) != "operator-data\n" {
		t.Fatalf("collision was changed: content=%q err=%v", content, err)
	}
}

func TestListenAuthenticatesKernelPeerAndExcludesSecondInstance(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	config := linuxTestConfig(t, filepath.Join(directory, "control.sock"))
	listener, err := Listen(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Cleanup() })
	if _, err := Listen(context.Background(), config); err == nil {
		t.Fatal("second listener succeeded")
	}
	done := make(chan AuthenticatedConn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			done <- connection.(AuthenticatedConn)
		}
	}()
	client, err := net.Dial("unix", config.Profile.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case connection := <-done:
		defer connection.Close()
		if connection.Principal().ID != "principal.test" {
			t.Fatalf("principal = %#v", connection.Principal())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("authenticated accept timed out")
	}
}

func TestCleanupLeavesReplacementUntouched(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	config := linuxTestConfig(t, filepath.Join(directory, "control.sock"))
	listener, err := Listen(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(config.Profile.SocketPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.Profile.SocketPath, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := listener.Cleanup(); err == nil {
		t.Fatal("Cleanup() did not report replacement")
	}
	if content, err := os.ReadFile(config.Profile.SocketPath); err != nil || string(content) != "replacement" {
		t.Fatalf("replacement changed: %q, %v", content, err)
	}
}
