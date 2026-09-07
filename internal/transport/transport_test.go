package transport

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type recordingExecutor struct {
	executable string
	arguments  []string
	result     Result
	err        error
	called     bool
	mutate     bool
}

func (executor *recordingExecutor) Execute(_ context.Context, executable string, arguments []string) (Result, error) {
	executor.called = true
	executor.executable = executable
	executor.arguments = arguments
	if executor.mutate && len(arguments) > 0 {
		arguments[0] = "executor-mutated"
	}
	return executor.result, executor.err
}

func TestExecuteDeliversRegisteredOperationExactly(t *testing.T) {
	t.Parallel()

	want := Result{ExitCode: 3, Stdout: []byte("out"), Stderr: []byte("err")}
	fake := &recordingExecutor{result: want}
	boundary, err := New([]Operation{{ID: "api", Executable: "vsk-labs"}}, fake)
	if err != nil {
		t.Fatal(err)
	}

	got, err := boundary.Execute(context.Background(), Request{OperationID: "api", Arguments: []string{"status", "--output", "json"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Execute() result = %#v, want %#v", got, want)
	}
	if fake.executable != "vsk-labs" || !reflect.DeepEqual(fake.arguments, []string{"status", "--output", "json"}) {
		t.Fatalf("invocation changed: %q %#v", fake.executable, fake.arguments)
	}
}

func TestMetacharactersRemainLiteralArguments(t *testing.T) {
	t.Parallel()

	fake := &recordingExecutor{}
	boundary, err := New([]Operation{{ID: "api", Executable: "vsk-labs"}}, fake)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"status; rm", "$(private-canary)", `name with spaces`, "*.db", "a|b", "<redirect"}
	if _, err := boundary.Execute(context.Background(), Request{OperationID: "api", Arguments: args}); err != nil {
		t.Fatal(err)
	}
	if fake.executable != "vsk-labs" || !reflect.DeepEqual(fake.arguments, args) {
		t.Fatalf("invocation changed: %q %#v", fake.executable, fake.arguments)
	}
}

func TestExecuteDefensivelyCopiesArguments(t *testing.T) {
	t.Parallel()

	fake := &recordingExecutor{mutate: true}
	boundary, err := New([]Operation{{ID: "api", Executable: "vsk-labs"}}, fake)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"status"}
	if _, err := boundary.Execute(context.Background(), Request{OperationID: "api", Arguments: args}); err != nil {
		t.Fatal(err)
	}
	if args[0] != "status" {
		t.Fatalf("caller arguments were mutated: %#v", args)
	}
	args[0] = "caller-mutated"
	if fake.arguments[0] != "executor-mutated" {
		t.Fatalf("executor arguments alias caller storage: %#v", fake.arguments)
	}
}

func TestNewCopiesTheOperationRegistry(t *testing.T) {
	t.Parallel()

	operations := []Operation{{ID: "api", Executable: "vsk-labs"}}
	fake := &recordingExecutor{}
	boundary, err := New(operations, fake)
	if err != nil {
		t.Fatal(err)
	}
	operations[0] = Operation{ID: "changed", Executable: "changed-tool"}

	if _, err := boundary.Execute(context.Background(), Request{OperationID: "api"}); err != nil {
		t.Fatal(err)
	}
	if fake.executable != "vsk-labs" {
		t.Fatalf("registered executable changed to %q", fake.executable)
	}
}

func TestNewRejectsDuplicateOperations(t *testing.T) {
	t.Parallel()

	_, err := New([]Operation{
		{ID: "api", Executable: "vsk-labs"},
		{ID: "api", Executable: "another-tool"},
	}, &recordingExecutor{})
	assertTransportError(t, err, generated.ErrorCodeInputInvalid, "operations")
}

func TestNewRejectsUnsafeExecutableIdentities(t *testing.T) {
	t.Parallel()

	unsafe := []string{
		"", "/usr/bin/vsk-labs", `C:\\tools\\vsk-labs.exe`, "vsk labs", "vsk-labs;rm",
		"sh", "bash", "zsh", "dash", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe", "BASH",
	}
	for _, executable := range unsafe {
		executable := executable
		t.Run(executable, func(t *testing.T) {
			t.Parallel()
			_, err := New([]Operation{{ID: "api", Executable: executable}}, &recordingExecutor{})
			assertTransportError(t, err, generated.ErrorCodeInputInvalid, "operations")
		})
	}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		operations []Operation
		executor   Executor
		target     string
	}{
		"missing executor": {
			operations: []Operation{{ID: "api", Executable: "vsk-labs"}},
			target:     "executor",
		},
		"empty operation id": {
			operations: []Operation{{ID: "", Executable: "vsk-labs"}},
			executor:   &recordingExecutor{},
			target:     "operations",
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := New(test.operations, test.executor)
			assertTransportError(t, err, generated.ErrorCodeInputInvalid, test.target)
		})
	}
}

func TestExecuteRejectsUnknownAndDirectDatabaseOperations(t *testing.T) {
	t.Parallel()

	fake := &recordingExecutor{}
	boundary, err := New([]Operation{{ID: "api", Executable: "vsk-labs"}}, fake)
	if err != nil {
		t.Fatal(err)
	}
	for _, operationID := range []string{"missing", "database-direct", "sqlite"} {
		_, err := boundary.Execute(context.Background(), Request{OperationID: operationID, Arguments: []string{"private.db"}})
		assertTransportError(t, err, generated.ErrorCodeInputInvalid, "request.operationId")
	}
	if fake.called {
		t.Fatal("executor called for an unregistered operation")
	}
}

func TestExecuteRejectsNULBeforeDispatch(t *testing.T) {
	t.Parallel()

	fake := &recordingExecutor{}
	boundary, err := New([]Operation{{ID: "api", Executable: "vsk-labs"}}, fake)
	if err != nil {
		t.Fatal(err)
	}
	_, err = boundary.Execute(context.Background(), Request{OperationID: "api", Arguments: []string{"safe", "private\x00canary"}})
	assertTransportError(t, err, generated.ErrorCodeInputInvalid, "request.arguments")
	if fake.called {
		t.Fatal("executor called for an argument containing NUL")
	}
}

func TestExecuteHonorsPreDispatchCancellation(t *testing.T) {
	t.Parallel()

	fake := &recordingExecutor{}
	boundary, err := New([]Operation{{ID: "api", Executable: "vsk-labs"}}, fake)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = boundary.Execute(ctx, Request{OperationID: "api"})
	assertTransportError(t, err, generated.ErrorCodeInterrupted, "transport")
	if fake.called {
		t.Fatal("executor called after context cancellation")
	}
}

func TestExecuteSanitizesExecutorFailures(t *testing.T) {
	t.Parallel()

	const canary = "private-executor-canary"
	fake := &recordingExecutor{err: errors.New(canary)}
	boundary, err := New([]Operation{{ID: "api", Executable: "vsk-labs"}}, fake)
	if err != nil {
		t.Fatal(err)
	}
	_, err = boundary.Execute(context.Background(), Request{OperationID: "api"})
	assertTransportError(t, err, generated.ErrorCodeDependencyUnavailable, "executor")
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("executor failure leaked private detail: %q", err)
	}
}

func TestExecuteMapsExecutorCancellation(t *testing.T) {
	t.Parallel()

	fake := &recordingExecutor{err: context.Canceled}
	boundary, err := New([]Operation{{ID: "api", Executable: "vsk-labs"}}, fake)
	if err != nil {
		t.Fatal(err)
	}
	_, err = boundary.Execute(context.Background(), Request{OperationID: "api"})
	assertTransportError(t, err, generated.ErrorCodeInterrupted, "transport")
}

func assertTransportError(t *testing.T, err error, code, target string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %s", code)
	}
	var transportError *Error
	if !errors.As(err, &transportError) {
		t.Fatalf("error type = %T, want *Error", err)
	}
	if transportError.Code != code || transportError.Target != target {
		t.Fatalf("error = %#v, want code %q target %q", transportError, code, target)
	}
}
