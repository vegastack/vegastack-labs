package debianaccess

import (
	"context"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

type RoleResult struct {
	Changed      bool
	Measurements []generated.AccessMeasurement
}
type Runtime interface {
	Inspect(context.Context, generated.HostActionBundle, generated.DebianAccessInput) (RollbackRecord, error)
	Arm(context.Context, RollbackRecord) error
	ApplyConfiguration(context.Context, generated.DebianAccessInput) (RoleResult, error)
	Confirm(context.Context, generated.HostActionBundle, generated.AccessConfirmInput) (RoleResult, error)
	Collect(context.Context, generated.HostActionBundle, generated.DebianAccessInput) (RoleResult, error)
	ProbeSource(context.Context, generated.HostActionBundle) (RoleResult, error)
}
type handler struct {
	action  string
	runtime Runtime
}

func NewHandler(actionID string, r Runtime) (hostaction.Handler, error) {
	if r == nil {
		return nil, errAccess
	}
	switch actionID {
	case "debian.access.apply", "debian.access.confirm", "debian.access.collect", "debian.access.probe-source":
		return handler{actionID, r}, nil
	}
	return nil, errAccess
}
func (h handler) Execute(ctx context.Context, b generated.HostActionBundle) (generated.HostActionResult, error) {
	result := generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0"}
	if b.ActionID != h.action || b.ActionVersion != "1.0.0" {
		return result, errAccess
	}
	bd, err := hostaction.BundleDigest(b)
	if err != nil {
		return result, err
	}
	result.BundleDigest = bd
	var observed RoleResult
	mutationAttempted := false
	switch h.action {
	case "debian.access.confirm":
		var in generated.AccessConfirmInput
		if b.VerificationEvidence == nil || b.VerificationEvidenceDigest == "" || generated.ValidateContractJSON(generated.SchemaIDAccessConfirmInput, []byte(b.ActionInput), generated.ContractExact) != nil || json.Unmarshal([]byte(b.ActionInput), &in) != nil {
			return result, errAccess
		}
		observed, err = h.runtime.Confirm(ctx, b, in)
		mutationAttempted = observed.Changed
	case "debian.access.probe-source":
		if b.VerificationEvidence != nil || b.VerificationEvidenceDigest != "" {
			return result, errAccess
		}
		observed, err = h.runtime.ProbeSource(ctx, b)
	default:
		if b.VerificationEvidence != nil || b.VerificationEvidenceDigest != "" {
			return result, errAccess
		}
		in, e := DecodeInput([]byte(b.ActionInput))
		if e != nil || in.HostID != b.HostID || in.HostIdentityDigest != b.HostIdentityDigest || in.AutomationUID != b.CallerUID {
			return result, errAccess
		}
		if h.action == "debian.access.collect" {
			observed, err = h.runtime.Collect(ctx, b, in)
		} else {
			var record RollbackRecord
			record, err = h.runtime.Inspect(ctx, b, in)
			if err == nil {
				err = h.runtime.Arm(ctx, record)
			}
			if err == nil {
				mutationAttempted = true
				observed, err = h.runtime.ApplyConfiguration(ctx, in)
			}
			if err == nil {
				for i := range observed.Measurements {
					observed.Measurements[i].RollbackRecordDigest = record.Digest()
				}
			}
		}
	}
	if err != nil {
		if !mutationAttempted {
			return result, err
		}
		result.Status = "partial"
		result.Changed = true
		result.EffectObserved = true
		result.Reason = "access-apply-incomplete"
		if h.action == "debian.access.confirm" {
			result.Reason = "access-confirm-incomplete"
		}
		result.ResultDigest = hostaction.ResultDigest(result)
		return result, nil
	}
	result.Status = "succeeded"
	result.Changed = observed.Changed
	result.EffectObserved = true
	result.Reason = "access-observed"
	result.ControlMeasurements = observed.Measurements
	for i := range result.ControlMeasurements {
		m := &result.ControlMeasurements[i]
		m.BundleDigest = bd
		m.MeasurementDigest = hostaction.MeasurementDigest(*m)
	}
	result.ResultDigest = hostaction.ResultDigest(result)
	if err = hostaction.ValidateResult(result); err != nil {
		return generated.HostActionResult{}, err
	}
	return result, nil
}
func (h handler) Verify(_ context.Context, b generated.HostActionBundle, r generated.HostActionResult) error {
	bd, err := hostaction.BundleDigest(b)
	if err != nil || r.BundleDigest != bd || b.ActionID != h.action {
		return errAccess
	}
	return hostaction.ValidateResult(r)
}

type dispatcher struct{ runtime Runtime }

func NewDispatcher(r Runtime) hostaction.Dispatcher { return dispatcher{r} }
func (d dispatcher) Lookup(id, version string) (hostaction.Handler, bool) {
	if version != "1.0.0" {
		return nil, false
	}
	h, err := NewHandler(id, d.runtime)
	return h, err == nil
}
