package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/cli"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type writerConflictOperations struct{ *Operations }

func (operations writerConflictOperations) Run(ctx context.Context, _ string) error {
	_, err := operations.openAuthorityWithPromotion(ctx, serverconfig.Profile{})
	return err
}

func assertWriterConflictCLI(t *testing.T, operations *Operations, wantCode, wantTarget string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	app := cli.New(&stdout, &stderr, operations.build, func() (string, error) { return "request-writer-conflict", nil }, cli.WithServerOperations(writerConflictOperations{operations}))
	code := app.Run(context.Background(), []string{"server", "run", "--config", "profile.json", "--output", "json"})
	var output generated.RunResult
	if code != generated.ErrorExitCodes[wantCode] || stderr.Len() != 0 || json.Unmarshal(stdout.Bytes(), &output) != nil {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if output.Status != generated.RunStatusFailed || len(output.Errors) != 1 || output.Errors[0].Code != wantCode || output.Errors[0].Target != wantTarget {
		t.Fatalf("unexpected writer refusal projection: %#v", output.Errors)
	}
}

func TestOpenAuthorityPreservesDatabaseWriterConflict(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("real store writer locking requires Linux")
	}
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	config := store.Config{DatabasePath: filepath.Join(directory, "control.db"), Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), BusyTimeout: 25 * time.Millisecond, ToolVersion: "test", BuildVersion: "test"}
	first, err := store.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	config.Mode = store.OpenExisting
	_, conflict := store.Open(ctx, config)
	var stored *store.StoreError
	if !errors.As(conflict, &stored) || stored.Code() != generated.ErrorCodeStateConflict || stored.Target() != "database-writer" || !stored.Retryable() {
		t.Fatalf("expected actual store writer conflict, got %v", conflict)
	}
	for _, wrapped := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrapped=%t", wrapped), func(t *testing.T) {
			input := conflict
			if wrapped {
				input = fmt.Errorf("startup: %w", input)
			}
			operations := &Operations{databasePath: config.DatabasePath, build: result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, openStore: func(context.Context, store.Config) (*store.Store, error) { return nil, input }}
			_, err := operations.openAuthorityWithPromotion(ctx, serverconfig.Profile{})
			stable, ok := failure.As(err)
			if !ok || stable.Code != generated.ErrorCodeStateConflict || stable.Target != "control-service-lock" || stable.Retryable != stored.Retryable() {
				t.Fatalf("writer conflict lost at server boundary: %v", err)
			}
			assertWriterConflictCLI(t, operations, generated.ErrorCodeStateConflict, "control-service-lock")
		})
	}
}

func TestOpenAuthorityDoesNotMapUnrelatedErrors(t *testing.T) {
	for _, input := range []error{errors.New("unclassified startup failure"), failure.New(generated.ErrorCodeStateConflict, "database-writer", true)} {
		operations := &Operations{databasePath: filepath.Join(t.TempDir(), "control.db"), build: result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, openStore: func(context.Context, store.Config) (*store.Store, error) { return nil, input }}
		if _, err := operations.openAuthorityWithPromotion(context.Background(), serverconfig.Profile{}); err != input {
			t.Fatalf("unrelated error changed: %v", err)
		}
		assertWriterConflictCLI(t, operations, generated.ErrorCodeIntegrityFailure, "server-operations")
	}
}
