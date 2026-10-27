//go:build linux

package cijobrunner

import (
	"context"
	"io"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

// SpecSource loads current protected configuration bound to the already verified
// signed action. It is not a replacement for hostaction authorization or lease admission.
type SpecSource interface {
	Load(context.Context, generated.HostActionBundle) (Spec, RuntimeProfile, error)
}
type CIHandler struct {
	source SpecSource
	docker *Docker
}

var _ hostaction.Handler = (*CIHandler)(nil)
var _ hostaction.CIHandler = (*CIHandler)(nil)

func NewCIHandler(source SpecSource, docker *Docker) (*CIHandler, error) {
	if source == nil || docker == nil {
		return nil, ErrBlocked
	}
	return &CIHandler{source, docker}, nil
}
func (h *CIHandler) Execute(context.Context, generated.HostActionBundle) (generated.HostActionResult, error) {
	return generated.HostActionResult{}, ErrBlocked
}
func (h *CIHandler) ExecuteCI(ctx context.Context, b generated.HostActionBundle, input io.ReadCloser, output io.Writer) (generated.HostActionResult, error) {
	var result generated.HostActionResult
	if h == nil || input == nil || output == nil || b.ActionID != hostaction.CIJobAction || b.ActionVersion != "1.0.0" {
		return result, ErrBlocked
	}
	bd, e := hostaction.BundleDigest(b)
	if e != nil {
		return result, ErrBlocked
	}
	s, p, e := h.source.Load(ctx, b)
	expiry, e2 := time.Parse(time.RFC3339, b.ExpiresAt)
	if e != nil || e2 != nil || p != h.docker.profile || s.Binding.PlanID != b.PlanID || s.Binding.LeaseID != b.LeaseID || b.RecoveryEpoch < 0 || s.Binding.Epoch != uint64(b.RecoveryEpoch) || s.Deadline.After(expiry) || ValidateSpec(s, p) != nil {
		return result, ErrBlocked
	}
	ctx, cancel := context.WithDeadline(ctx, s.Deadline)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { input.Close() })
	defer stop()
	session := NewStream(input, output)
	session.onDecision = func() { go func() { _, _ = session.read(ctx); cancel() }() }
	receipt, runErr := h.docker.Run(ctx, s, session)
	result = generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: bd, Status: "succeeded", Changed: true, EffectObserved: receipt.Stopped && receipt.VolumesRemoved, Reason: "ci-job-complete"}
	if runErr != nil {
		if receipt.Stage == "preflight" {
			return generated.HostActionResult{}, runErr
		}
		result.Status = "partial"
		result.Reason = "ci-job-incomplete"
	}
	result.ResultDigest = hostaction.ResultDigest(result)
	if session.write(context.WithoutCancel(ctx), frame{Kind: "complete", Completion: &Completion{Succeeded: runErr == nil, LogDigest: receipt.LogDigest, Stopped: receipt.Stopped, VolumesRemoved: receipt.VolumesRemoved}}) != nil {
		return result, ErrProtocol
	}
	return result, nil
}
func (h *CIHandler) Verify(_ context.Context, b generated.HostActionBundle, r generated.HostActionResult) error {
	d, e := hostaction.BundleDigest(b)
	if e != nil || b.ActionID != hostaction.CIJobAction || d != r.BundleDigest || hostaction.ValidateResult(r) != nil {
		return ErrBlocked
	}
	return nil
}
