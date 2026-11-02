//go:build linux

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/cli"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// The test supplies the already selected profile and peer identity. Everything
// from CLI parsing through local API transport, API authorization and collection
// is real. This does not qualify profile loading, OS-peer identity or installation.
type operationsCLIProfile struct {
	*Operations
	client  localapi.Client
	profile serverconfig.Profile
}

func (c operationsCLIProfile) OperationsStatus(ctx context.Context, path string, observe bool) (localapi.TypedResponse[generated.OperationsStatusData], error) {
	if path != "fixture/profile.json" {
		return localapi.TypedResponse[generated.OperationsStatusData]{}, fmt.Errorf("unexpected fixture profile")
	}
	return c.client.OperationsStatus(ctx, c.profile, observe)
}

func operationsCLIWorkflow(t *testing.T, ctx context.Context, m *operationsMonitoring) func(string, bool) (generated.RunResult, string, int) {
	t.Helper()
	requestID := func() (string, error) { return "operations-cli-fixture", nil }
	factory := result.NewFactory(m.build, requestID)
	app, err := api.NewApplication(api.Config{Authority: m.s, Authorizer: store.NewReadAuthorizer(m.s), Reads: store.NewReadRepository(m.s), Results: factory})
	if err != nil {
		t.Fatal(err)
	}
	if err := api.RegisterOperationsMonitoring(app, api.OperationsMonitoring{Status: m.status, Observe: m.observe}); err != nil {
		t.Fatal(err)
	}
	// Keep the Unix socket below the OS path length limit, independently of the
	// checkout path. This listener has no TCP or fleet target.
	directory, err := os.MkdirTemp("", "vsk-operations-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	socket := filepath.Join(directory, "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	principal, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		t.Fatal("missing fixture peer identity")
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.ServeHTTP(w, r.WithContext(identity.WithVerifiedPrincipal(r.Context(), principal)))
	})}
	go srv.Serve(listener)
	t.Cleanup(func() { srv.Close() })
	control := operationsCLIProfile{client: localapi.NewClient(factory), profile: serverconfig.Profile{SocketPath: socket}}
	return func(action string, human bool) (generated.RunResult, string, int) {
		t.Helper()
		var out, diagnostics bytes.Buffer
		args := []string{"operations", action, "--config", "fixture/profile.json"}
		if !human {
			args = append(args, "--output", "json")
		}
		code := cli.New(&out, &diagnostics, m.build, requestID, cli.WithControlOperations(control, nil)).Run(ctx, args)
		var envelope generated.RunResult
		if !human && json.Unmarshal(out.Bytes(), &envelope) != nil {
			t.Fatal("CLI did not return its JSON envelope")
		}
		if code == 0 && diagnostics.Len() != 0 {
			t.Fatal("successful command wrote diagnostics")
		}
		return envelope, out.String(), code
	}
}
