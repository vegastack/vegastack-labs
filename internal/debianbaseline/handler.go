package debianbaseline

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

type Runtime interface {
	Inspect(context.Context, generated.HostActionBundle, generated.DebianBaselineInput) error
	Apply(context.Context, generated.HostActionBundle, generated.DebianBaselineInput) (Result, error)
	Collect(context.Context, generated.HostActionBundle, generated.DebianBaselineInput) (Result, error)
}
type handler struct {
	action         string
	runtime        Runtime
	verifyRecovery func(context.Context, generated.VolumeRecoveryInput) ([]generated.AccessMeasurement, error)
}

func NewHandler(action string, r Runtime) (hostaction.Handler, error) {
	if r == nil {
		return nil, errBaseline
	}
	switch action {
	case "debian.baseline.apply", "debian.baseline.collect", "debian.aide.initialize", "debian.aide.refresh", "debian.volume.observe", "debian.volume-recovery.verify":
		return handler{action: action, runtime: r, verifyRecovery: VerifyVolumeRecovery}, nil
	}
	return nil, errBaseline
}
func (h handler) Execute(ctx context.Context, b generated.HostActionBundle) (generated.HostActionResult, error) {
	result := generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0"}
	if b.ActionID != h.action || b.ActionVersion != "1.0.0" || b.VerificationEvidence != nil || b.VerificationEvidenceDigest != "" {
		return result, errBaseline
	}
	bd, e := hostaction.BundleDigest(b)
	if e != nil {
		return result, e
	}
	result.BundleDigest = bd
	var out Result
	if h.action == "debian.volume-recovery.verify" {
		in, e := DecodeRecoveryInput([]byte(b.ActionInput))
		if e != nil {
			return result, e
		}
		// Same exact native profile preflight applies on the executing custodian.
		check := generated.DebianBaselineInput{HostID: in.HostID, HostIdentityDigest: in.HostIdentityDigest, ProfileLock: in.ProfileLock, ProfileLockDigest: in.ProfileLockDigest, AutomationUID: in.AutomationUID}
		if e = h.runtime.Inspect(ctx, b, check); e != nil {
			return result, e
		}
		out.Measurements, e = h.verifyRecovery(ctx, in)
		if e != nil {
			return result, e
		}
	} else {
		in, err := DecodeInput([]byte(b.ActionInput))
		if err != nil {
			return result, err
		}
		if err = h.runtime.Inspect(ctx, b, in); err != nil {
			return result, err
		}
		switch h.action {
		case "debian.baseline.collect":
			out, e = h.runtime.Collect(ctx, b, in)
		case "debian.volume.observe":
			out.Measurements, e = ObserveVolumes(ctx, in)
		default:
			out, e = h.runtime.Apply(ctx, b, in)
		}
	}
	if e != nil && !out.Changed {
		return result, e
	}
	result.Changed = out.Changed
	result.EffectObserved = out.Changed || e == nil
	result.ControlMeasurements = out.Measurements
	result.Status = "succeeded"
	result.Reason = "native-baseline-observed"
	if e != nil {
		result.Status = "partial"
		result.Reason = "baseline-effect-incomplete"
	}
	if h.action == "debian.baseline.apply" || h.action == "debian.aide.initialize" || h.action == "debian.aide.refresh" {
		for _, m := range result.ControlMeasurements {
			if m.Status != "passed" {
				result.Status = "partial"
				result.Reason = "baseline-verification-incomplete"
			}
		}
	}
	for i := range result.ControlMeasurements {
		m := &result.ControlMeasurements[i]
		m.BundleDigest = bd
		m.MeasurementDigest = hostaction.MeasurementDigest(*m)
	}
	result.ResultDigest = hostaction.ResultDigest(result)
	if hostaction.ValidateResult(result) != nil {
		return generated.HostActionResult{}, errBaseline
	}
	return result, nil
}
func (h handler) Verify(_ context.Context, b generated.HostActionBundle, r generated.HostActionResult) error {
	bd, e := hostaction.BundleDigest(b)
	if e != nil || b.ActionID != h.action || r.BundleDigest != bd {
		return errBaseline
	}
	return hostaction.ValidateResult(r)
}

type dispatcher struct{ runtime Runtime }

func NewDispatcher(r Runtime) hostaction.Dispatcher { return dispatcher{r} }
func (d dispatcher) Lookup(id, version string) (hostaction.Handler, bool) {
	if version != "1.0.0" {
		return nil, false
	}
	h, e := NewHandler(id, d.runtime)
	return h, e == nil
}
