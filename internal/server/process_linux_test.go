//go:build linux

package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

const processHelperEnvironment = "VSK_SERVER_PROCESS_HELPER"

type processApplication struct {
	readyPath string
}

func (application processApplication) Start(context.Context) error {
	return os.WriteFile(application.readyPath, []byte("ready\n"), 0o600)
}

func (processApplication) Health(context.Context) (ApplicationHealth, error) {
	return ApplicationHealth{RecoveryEpoch: 7, StateRevision: 11}, nil
}

func (processApplication) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	http.NotFound(writer, nil)
}

func (processApplication) Shutdown(context.Context) error { return nil }

func TestServerProcessSignals(t *testing.T) {
	if os.Getenv(processHelperEnvironment) == "1" {
		runServerProcessHelper(t)
		return
	}
	for _, signalValue := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		signalValue := signalValue
		t.Run(signalValue.String(), func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			socketPath := filepath.Join(directory, "control.sock")
			readyPath := filepath.Join(directory, "ready")
			command := exec.Command(os.Args[0], "-test.run=^TestServerProcessSignals$")
			command.Env = append(os.Environ(),
				processHelperEnvironment+"=1",
				"VSK_SERVER_SOCKET="+socketPath,
				"VSK_SERVER_READY="+readyPath,
			)
			var output bytes.Buffer
			command.Stdout = &output
			command.Stderr = &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(10 * time.Second)
			for {
				if _, err := os.Stat(readyPath); err == nil {
					break
				}
				if time.Now().After(deadline) {
					_ = command.Process.Kill()
					t.Fatalf("server helper did not become ready: %s", output.String())
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err := command.Process.Signal(signalValue); err != nil {
				t.Fatal(err)
			}
			waitDone := make(chan error, 1)
			go func() { waitDone <- command.Wait() }()
			select {
			case err := <-waitDone:
				if err != nil {
					t.Fatalf("server helper exit: %v: %s", err, output.String())
				}
			case <-time.After(10 * time.Second):
				_ = command.Process.Kill()
				t.Fatal("server helper did not drain")
			}
			if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("owned socket remains after drain: %v", err)
			}
		})
	}
}

func runServerProcessHelper(t *testing.T) {
	uid := uint32(os.Geteuid())
	profile := serverconfig.Profile{
		SocketPath:        os.Getenv("VSK_SERVER_SOCKET"),
		SocketOwnerUID:    uid,
		SocketMode:        0o600,
		ShutdownGrace:     5 * time.Second,
		PrincipalBindings: []identity.Binding{{UID: uid, PrincipalID: "principal.process-test"}},
	}
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) {
		return "request-00000000000000000000000000000000", nil
	})
	service, err := New(Config{
		Profile:     profile,
		Application: processApplication{readyPath: os.Getenv("VSK_SERVER_READY")},
		Results:     factory,
		PlatformProbe: staticPlatformProbe{platform: Platform{
			OS: "linux", Architecture: "amd64", Distribution: "debian", Major: 13,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := service.Run(ctx); err != nil {
		t.Fatal(err)
	}
}
