//go:build linux

package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
)

// TestPhase5AcceptanceBuiltProcessRecoveryAndIsolation composes the Phase 5
// surface parity proof with a real built vsk-labs server, its persisted SQLite
// authority and a synthetic identity provider. The server is killed rather
// than gracefully drained, restarted against the same state while the provider
// remains unavailable, and must retain local inspection authority.
func TestPhase5AcceptanceBuiltProcessRecoveryAndIsolation(t *testing.T) {
	t.Run("cli-api-console-parity", runPhase5SurfaceParity)
	t.Run("process-kill-provider-outage-local-inspection", func(t *testing.T) {
		fixture := newPhase3ExecutableFixture(t)
		fixture.providerOnline.Store(false)
		assertPhase5LocalInspectionAvailable(t, fixture, "before-kill")

		if err := fixture.command.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-fixture.done:
			if err == nil {
				t.Fatal("killed server reported a graceful exit")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("killed server process did not exit")
		}

		fixture.command = exec.Command(fixture.binaryPath, "server", "run", "--config", fixture.configPath, "--output", "json")
		fixture.command.Env = append(os.Environ(), "SSL_CERT_FILE="+filepath.Join(filepath.Dir(fixture.configPath), "jwks-ca.pem"))
		fixture.serverStdout = &boundedProbeOutput{limit: 16 * 1024}
		fixture.serverStderr = &boundedProbeOutput{limit: 512}
		fixture.command.Stdout = fixture.serverStdout
		fixture.command.Stderr = fixture.serverStderr
		fixture.done = make(chan error, 1)
		if err := fixture.command.Start(); err != nil {
			t.Fatal(err)
		}
		go func() { fixture.done <- fixture.command.Wait() }()

		deadline := time.Now().Add(10 * time.Second)
		for {
			if phase5LocalInspectionAvailable(fixture) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("restarted server did not restore local inspection")
			}
			time.Sleep(20 * time.Millisecond)
		}
		assertPhase5LocalInspectionAvailable(t, fixture, "after-restart")
	})
}

func phase5LocalInspectionAvailable(fixture *phase3ExecutableFixture) bool {
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "phase5-test", ReleaseBuildID: "phase5-test"}, func() (string, error) {
		return "request-phase5-built-process", nil
	})
	status, err := localapi.NewClient(factory).Status(context.Background(), fixture.profile)
	return err == nil && status.ExitCode == 0 && status.Status.ReadAvailable
}

func assertPhase5LocalInspectionAvailable(t *testing.T, fixture *phase3ExecutableFixture, stage string) {
	t.Helper()
	if !phase5LocalInspectionAvailable(fixture) {
		t.Fatalf("local inspection unavailable at %s", stage)
	}
}
