package backup

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// ConsistencyOutcome records the registered hook that bracketed a capture and
// whether it finished successfully.
type ConsistencyOutcome struct {
	HookID  string
	Success bool
}

// CaptureResult carries the consistent snapshot description and the exact
// consistency outcome. It contains no secret material.
type CaptureResult struct {
	Snapshot    store.OnlineSnapshotResult
	Consistency ConsistencyOutcome
}

// Capture runs one consistent capture of the policy's registered source through
// the store-owned online snapshot port, bracketed by the policy's registered
// consistency hook. Guarantees:
//   - only a registered hook and the store-owned snapshot port are used; the
//     live SQLite file is never opened by this package;
//   - after a successful Begin, Finish always runs exactly once, with
//     success=false on any capture failure;
//   - no snapshot is returned on any failure.
func Capture(ctx context.Context, source PolicySource, online store.OnlineSnapshotSource, registry *HookRegistry, destination string) (CaptureResult, error) {
	if online == nil || registry == nil || destination == "" || source.PolicyDigest == "" {
		return CaptureResult{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "backup-capture", false)
	}
	hook, ok := registry.Resolve(source.Policy.ConsistencyHookID)
	if !ok {
		return CaptureResult{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "backup-consistency-hook", false)
	}
	token, err := hook.Begin(ctx, source)
	if err != nil {
		return CaptureResult{}, failure.New(generated.ErrorCodeDependencyUnavailable, "backup-consistency-hook", false)
	}
	result, captureErr := online.OnlineSnapshot(ctx, store.OnlineSnapshotRequest{Destination: destination, Expected: source.Expectation})
	success := captureErr == nil
	finishErr := hook.Finish(ctx, token, success)
	if captureErr != nil {
		return CaptureResult{}, captureError(captureErr, "backup-capture")
	}
	if finishErr != nil {
		return CaptureResult{}, failure.New(generated.ErrorCodeDependencyUnavailable, "backup-consistency-hook", false)
	}
	return CaptureResult{Snapshot: result, Consistency: ConsistencyOutcome{HookID: source.Policy.ConsistencyHookID, Success: true}}, nil
}

// captureError normalizes a store or failure error into a sanitized boundary
// error, preserving its stable code so callers can classify the failure.
func captureError(err error, target string) error {
	code := store.Code(err)
	if code == "" {
		if stable, ok := failure.As(err); ok {
			code = stable.Code
		} else {
			code = generated.ErrorCodeExecutionFailed
		}
	}
	return failure.New(code, target, false)
}
