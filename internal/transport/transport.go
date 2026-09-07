// Package transport defines the provider-neutral boundary for invoking a
// registered executable with a direct argument array.
package transport

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

var executablePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

var shellExecutables = map[string]struct{}{
	"bash":           {},
	"cmd":            {},
	"cmd.exe":        {},
	"dash":           {},
	"fish":           {},
	"powershell":     {},
	"powershell.exe": {},
	"pwsh":           {},
	"pwsh.exe":       {},
	"sh":             {},
	"zsh":            {},
}

// Operation binds a trusted operation identity to a direct executable name.
type Operation struct {
	ID         string
	Executable string
}

// Request selects a registered operation and supplies its literal arguments.
type Request struct {
	OperationID string
	Arguments   []string
}

// Result is the executor's process-independent result.
type Result struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

// Executor performs a direct executable invocation. Implementations live
// outside this boundary and must not reinterpret arguments as shell text.
type Executor interface {
	Execute(context.Context, string, []string) (Result, error)
}

// Error is a stable, sanitized transport failure.
type Error struct {
	Code   string
	Target string
}

func (err *Error) Error() string {
	return err.Code + ": transport request rejected (" + err.Target + ")"
}

// Transport dispatches only operations registered at construction time.
type Transport struct {
	operations map[string]string
	executor   Executor
}

// New validates and copies the trusted operation registry.
func New(operations []Operation, executor Executor) (*Transport, error) {
	if executor == nil {
		return nil, transportError(generated.ErrorCodeInputInvalid, "executor")
	}

	registered := make(map[string]string, len(operations))
	for _, operation := range operations {
		if operation.ID == "" {
			return nil, transportError(generated.ErrorCodeInputInvalid, "operations")
		}
		if !validExecutable(operation.Executable) {
			return nil, transportError(generated.ErrorCodeInputInvalid, "operations")
		}
		if _, exists := registered[operation.ID]; exists {
			return nil, transportError(generated.ErrorCodeInputInvalid, "operations")
		}
		registered[operation.ID] = operation.Executable
	}

	return &Transport{operations: registered, executor: executor}, nil
}

// Execute validates the request and passes a copied argument array directly to
// the registered executor. Argument metacharacters remain literal.
func (transport *Transport) Execute(ctx context.Context, request Request) (Result, error) {
	if transport == nil || transport.executor == nil {
		return Result{}, transportError(generated.ErrorCodeInputInvalid, "transport")
	}
	if ctx == nil {
		return Result{}, transportError(generated.ErrorCodeInputInvalid, "context")
	}
	if ctx.Err() != nil {
		return Result{}, transportError(generated.ErrorCodeInterrupted, "transport")
	}

	executable, registered := transport.operations[request.OperationID]
	if !registered {
		return Result{}, transportError(generated.ErrorCodeInputInvalid, "request.operationId")
	}
	for _, argument := range request.Arguments {
		if strings.ContainsRune(argument, '\x00') {
			return Result{}, transportError(generated.ErrorCodeInputInvalid, "request.arguments")
		}
	}

	arguments := append([]string(nil), request.Arguments...)
	result, err := transport.executor.Execute(ctx, executable, arguments)
	if err == nil {
		return result, nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		return Result{}, transportError(generated.ErrorCodeInterrupted, "transport")
	}
	return Result{}, transportError(generated.ErrorCodeDependencyUnavailable, "executor")
}

func validExecutable(executable string) bool {
	if !executablePattern.MatchString(executable) {
		return false
	}
	_, shell := shellExecutables[strings.ToLower(executable)]
	return !shell
}

func transportError(code, target string) error {
	return &Error{Code: code, Target: target}
}
