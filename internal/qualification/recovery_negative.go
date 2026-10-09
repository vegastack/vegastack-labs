package qualification

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

type replacementNegativeAPI interface {
	GetHostReplacement(context.Context, serverconfig.Profile, string) (localapi.TypedResponse[generated.HostReplacementState], error)
	SubmitHostAction(context.Context, serverconfig.Profile, generated.HostActionRequest) (localapi.TypedResponse[generated.HostActionSubmission], error)
	PrepareHostReplacement(context.Context, serverconfig.Profile, generated.HostReplacementRequest) (localapi.TypedResponse[generated.HostReplacementSubmission], error)
}

// ExecuteReplacementNegative issues only the two finite ordinary API attempts
// selected by a protected preparation slot. Outcomes are observed here; no input
// field can assert that an attempt was denied or ownership was preserved.
func ExecuteReplacementNegative(ctx context.Context, client localapi.Client, profile serverconfig.Profile, in generated.NativeReplacementRecoveryRequest) (generated.NativeReplacementRecoveryAttempt, error) {
	return executeReplacementNegative(ctx, client, profile, in)
}
func executeReplacementNegative(ctx context.Context, client replacementNegativeAPI, profile serverconfig.Profile, in generated.NativeReplacementRecoveryRequest) (generated.NativeReplacementRecoveryAttempt, error) {
	out := generated.NativeReplacementRecoveryAttempt{Schema: generated.SchemaIDNativeReplacementRecoveryAttempt, SchemaVersion: "1.0.0", Kind: in.Kind}
	if ctx == nil || client == nil || !exactNativeJSON(generated.SchemaIDNativeReplacementRecoveryRequest, in) {
		return out, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	before, err := client.GetHostReplacement(ctx, profile, in.ReplacementID)
	if err != nil || before.ExitCode != 0 || before.Data.ReplacementID != in.ReplacementID || before.Data.BindingDigest != in.BindingDigest || before.Data.RestorationClass != "control-database" || before.Data.FreezeEventDigest == "" {
		return out, ErrUnavailable
	}
	out.Before = before.Data
	switch in.Kind {
	case "old-host-return":
		if in.Action == nil || in.Replacement != nil || before.Data.Status != "committed" {
			return out, ErrUnavailable
		}
		q := *in.Action
		q.ExpectedStateRevision = before.Result.StateRevision
		q.RecoveryEpoch = before.Result.RecoveryEpoch
		if q.ActionID != "debian.baseline.collect" || q.HostID != before.Data.OldHostID || q.ConsoleConfirmation.HostIdentityDigest != before.Data.OldIdentityDigest || hostaction.ValidateRequest(q) != nil {
			return out, ErrUnavailable
		}
		in.Action = &q
		response, e := client.SubmitHostAction(ctx, profile, q)
		if e != nil {
			return out, ErrUnavailable
		}
		out.Response, err = finiteNegativeResponse(response.Result, response.ExitCode, "api.v1.host-actions.draft", "PREREQUISITE_BLOCKED", "host-action")
	case "concurrent-replacement":
		if in.Replacement == nil || in.Action != nil || before.Data.Status != "frozen" {
			return out, ErrUnavailable
		}
		q := *in.Replacement
		q.ExpectedStateRevision = before.Result.StateRevision
		q.RecoveryEpoch = before.Result.RecoveryEpoch
		if q.Operation != "freeze" || q.ReplacementID == in.ReplacementID || q.ExpectedDeclarationRevision != 0 || hostreplacement.ValidateInput(q) != nil {
			return out, ErrUnavailable
		}
		original := q
		original.ReplacementID = in.ReplacementID
		if hostreplacement.BindingDigest(original) != in.BindingDigest {
			return out, ErrUnavailable
		}
		in.Replacement = &q
		response, e := client.PrepareHostReplacement(ctx, profile, q)
		if e != nil {
			return out, ErrUnavailable
		}
		out.Response, err = finiteNegativeResponse(response.Result, response.ExitCode, "api.v1.host-replacements.create", "PLAN_STALE", "host-replacement")
		if err != nil {
			return out, err
		}
		lookup, e := client.GetHostReplacement(ctx, profile, q.ReplacementID)
		if e != nil {
			return out, ErrUnavailable
		}
		out.CompetingLookup, err = finiteNegativeResponse(lookup.Result, lookup.ExitCode, "api.v1.host-replacements.get", "RESOURCE_NOT_FOUND", "host-replacement")
	default:
		return out, ErrUnavailable
	}
	if err != nil {
		return out, err
	}
	after, err := client.GetHostReplacement(ctx, profile, in.ReplacementID)
	if err != nil || after.ExitCode != 0 || !sameReplacementOwnership(before.Data, after.Data) {
		return out, ErrUnavailable
	}
	out.After = after.Data
	out.Request = &in
	out.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if !exactNativeJSON(generated.SchemaIDNativeReplacementRecoveryAttempt, out) {
		return out, ErrUnavailable
	}
	return out, nil
}
func finiteNegativeResponse(r generated.RunResult, exit int, command, code, target string) (*generated.NativeFiniteResponse, error) {
	if exit == 0 || r.Status != "failed" || r.Changed || r.RunID != nil || r.Command != command || r.RequestID == "" || len(r.Errors) != 1 || r.Errors[0].Code != code || r.Errors[0].Target != target {
		return nil, ErrUnavailable
	}
	v := &generated.NativeFiniteResponse{Schema: generated.SchemaIDNativeFiniteResponse, SchemaVersion: "1.0.0", ResponseCommand: r.Command, ResponseRequestID: r.RequestID, ErrorCode: r.Errors[0].Code, ErrorTarget: r.Errors[0].Target, ExitCode: int64(exit), Changed: r.Changed}
	if !exactNativeJSON(generated.SchemaIDNativeFiniteResponse, v) {
		return nil, ErrUnavailable
	}
	return v, nil
}
func sameReplacementOwnership(a, b generated.HostReplacementState) bool {
	// Read envelopes expose the current global revision, which an independent
	// failure audit may advance. Every replacement field remains exact.
	a.StateRevision = 0
	b.StateRevision = 0
	return hostaction.Digest(a) == hostaction.Digest(b)
}
